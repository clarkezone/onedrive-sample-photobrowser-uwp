namespace OneDrivePhotoBrowser.Controllers
{
    using Microsoft.Graph;
    using System;
    using System.Threading.Tasks;
    using Windows.Security.Authentication.Web.Core;
    using Windows.Security.Credentials;
    using Windows.Storage;
    using Windows.UI.ApplicationSettings;
    using System.Net.Http;
    using System.Diagnostics;

    internal class AccountController : IAuthenticationProvider
    {
        private const string StoredAccountKey = "CurrentUserId";
        private const string MicrosoftAccountProviderId = "https://login.microsoft.com";
        private const string ConsumerAuthority = "consumers";
        private const string AccountScopeRequested = "wl.basic";
        private const string AccountClientId = "none";
        private TaskCompletionSource<bool> signinTask;

        public string CurrentToken { get; private set; }

        public AccountController()
        {
            AccountsSettingsPane.GetForCurrentView().AccountCommandsRequested += this.OnAccountCommandsRequested;
        }

        ~AccountController()
        {
            AccountsSettingsPane.GetForCurrentView().AccountCommandsRequested -= this.OnAccountCommandsRequested;
        }

        public event EventHandler LoggedIn;

        public event EventHandler LoggedOut;

        public void ResetCurrentTokenAsync()
        {
            this.CurrentToken = string.Empty;
        }

        public async Task RefreshCurrentTokenAsync(bool force)
        {
            if (string.IsNullOrEmpty(this.CurrentToken) || force)
            {
                var token = await this.GetTokenAsync();
                this.CurrentToken = token;
            }
        }

        public Task AuthenticateRequestAsync(HttpRequestMessage request)
        {
            if (!string.IsNullOrEmpty(this.CurrentToken))
            {
                request.Headers.Add(nameof(System.Net.HttpRequestHeader.Authorization), $"bearer {this.CurrentToken}");
            }

            TaskCompletionSource<bool> tcs = new TaskCompletionSource<bool>();
            tcs.SetResult(true);
            return tcs.Task;
        }

        public async Task PromptUserSignin()
        {
            if (signinTask == null)
            {
                signinTask = new TaskCompletionSource<bool>();

                if (!this.HasSavedCreds())
                {
                    AccountsSettingsPane.Show();

                    //signinTask will be signalled after the picker returns
                    //TODO: check cancel / failure

                    await signinTask.Task;
                } else
                {
                    await RefreshCurrentTokenAsync(false);
                }

            } else
            {
                throw new Exception("Signin already in progress");
            }
        }

        private bool HasSavedCreds()
        {
            string providerId = ApplicationData.Current.LocalSettings.Values["CurrentUserProviderId"]?.ToString();
            string accountId = ApplicationData.Current.LocalSettings.Values["CurrentUserId"]?.ToString();

            if (!string.IsNullOrEmpty(providerId) && !string.IsNullOrEmpty(accountId))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        private async Task<string> GetTokenAsync()
        {
            string providerId = ApplicationData.Current.LocalSettings.Values["CurrentUserProviderId"]?.ToString();
            string accountId = ApplicationData.Current.LocalSettings.Values["CurrentUserId"]?.ToString();

            if (providerId == null || accountId == null)
            {
                return string.Empty;
            }

            WebAccountProvider provider = await WebAuthenticationCoreManager.FindAccountProviderAsync(providerId);
            WebAccount account = await WebAuthenticationCoreManager.FindAccountAsync(provider, accountId);

            WebTokenRequest request = new WebTokenRequest(provider, "wl.basic");

            WebTokenRequestResult result = await WebAuthenticationCoreManager.GetTokenSilentlyAsync(request, account);
            if (result.ResponseStatus == WebTokenRequestStatus.UserInteractionRequired)
            {
                // Unable to get a token silently - you'll need to show the UI
                return string.Empty;
            }
            else if (result.ResponseStatus == WebTokenRequestStatus.Success)
            {
                // Success
                return result.ResponseData[0].Token;
            }
            else
            {
                // Other error
                return string.Empty;
            }
        }

      

        private async Task AddWebAccount(AccountsSettingsPaneCommandsRequestedEventArgs e)
        {
            var provider = await WebAuthenticationCoreManager.FindAccountProviderAsync(MicrosoftAccountProviderId, ConsumerAuthority);

            var accountID = (string)ApplicationData.Current.LocalSettings.Values[StoredAccountKey];
            var account = await WebAuthenticationCoreManager.FindAccountAsync(provider, accountID);

            if (account == null)
            {
                // The account has most likely been deleted in Windows settings
                // Unless there would be significant data loss, you should just delete the account
                // If there would be significant data loss, prompt the user to either re-add the account, or to remove it
                ApplicationData.Current.LocalSettings.Values.Remove(StoredAccountKey);
            }

            WebAccountCommand command = new WebAccountCommand(account, this.WebAccountInvoked, SupportedWebAccountActions.Remove);
            e.WebAccountCommands.Add(command);
        }

        // This event handler is called when the Account settings pane is to be launched.
        private async void OnAccountCommandsRequested(
            AccountsSettingsPane sender,
            AccountsSettingsPaneCommandsRequestedEventArgs e)
        {
            // In order to make async calls within this callback, the deferral object is needed
            AccountsSettingsPaneEventDeferral deferral = e.GetDeferral();

            // This scenario only lets the user have one account at a time.
            // If there already is an account, we do not include a provider in the list
            // This will prevent the add account button from showing up.
            bool isPresent = ApplicationData.Current.LocalSettings.Values.ContainsKey(StoredAccountKey);

            if (isPresent)
            {
                await this.AddWebAccount(e);
            }
            else
            {
                await this.AddWebAccountProvider(e);
            }



            deferral.Complete();
        }

        private async void WebAccountInvoked(WebAccountCommand command, WebAccountInvokedArgs args)
        {
            if (args.Action == WebAccountAction.Remove)
            {
                // rootPage.NotifyUser("Removing account", NotifyType.StatusMessage);
                await this.LogoffAndRemoveAccount();
            }
        }

        private async Task AddWebAccountProvider(AccountsSettingsPaneCommandsRequestedEventArgs e)
        {
            // FindAccountProviderAsync returns the WebAccountProvider of an installed plugin
            // The Provider and Authority specifies the specific plugin
            // This scenario only supports Microsoft accounts.

            // The Microsoft account provider is always present in Windows 10 devices, as is the Azure AD plugin.
            // If a non-installed plugin or incorect identity is specified, FindAccountProviderAsync will return null
            WebAccountProvider provider = await WebAuthenticationCoreManager.FindAccountProviderAsync(MicrosoftAccountProviderId, ConsumerAuthority);

            WebAccountProviderCommand providerCommand = new WebAccountProviderCommand(provider, this.WebAccountProviderCommandInvoked);
            e.WebAccountProviderCommands.Add(providerCommand);
        }

        private async Task LogoffAndRemoveAccount()
        {
            if (ApplicationData.Current.LocalSettings.Values.ContainsKey(StoredAccountKey))
            {
                WebAccountProvider providertoDelete = await WebAuthenticationCoreManager.FindAccountProviderAsync(MicrosoftAccountProviderId, ConsumerAuthority);

                WebAccount accountToDelete = await WebAuthenticationCoreManager.FindAccountAsync(providertoDelete, (string)ApplicationData.Current.LocalSettings.Values[StoredAccountKey]);

                if (accountToDelete != null)
                {
                    await accountToDelete.SignOutAsync();
                }

                ApplicationData.Current.LocalSettings.Values.Remove(StoredAccountKey);

                this.LoggedOut?.Invoke(this, null);
            }
        }

        private async void WebAccountProviderCommandInvoked(WebAccountProviderCommand command)
        {
            // ClientID is ignored by MSA
            await this.RequestTokenAndSaveAccount(command.WebAccountProvider, AccountScopeRequested, AccountClientId);
        }

        private async Task RequestTokenAndSaveAccount(WebAccountProvider Provider, string Scope, string ClientID)
        {

            WebTokenRequest webTokenRequest = new WebTokenRequest(Provider, Scope, ClientID);

            // rootPage.NotifyUser("Requesting Web Token", NotifyType.StatusMessage);

            // If the user selected a specific account, RequestTokenAsync will return a token for that account.
            // The user may be prompted for credentials or to authorize using that account with your app
            // If the user selected a provider, the user will be prompted for credentials to login to a new account
            WebTokenRequestResult webTokenRequestResult = await WebAuthenticationCoreManager.RequestTokenAsync(webTokenRequest);

            // If a token was successfully returned, then store the WebAccount Id into local app data
            // This Id can be used to retrieve the account whenever needed. To later get a token with that account
            // First retrieve the account with FindAccountAsync, and include that webaccount
            // as a parameter to RequestTokenAsync or RequestTokenSilentlyAsync
            if (webTokenRequestResult.ResponseStatus == WebTokenRequestStatus.Success)
            {
                ApplicationData.Current.LocalSettings.Values.Remove(StoredAccountKey);

                // ApplicationData.Current.LocalSettings.Values[StoredAccountKey] = webTokenRequestResult.ResponseData[0].WebAccount.Id;
                ApplicationData.Current.LocalSettings.Values["CurrentUserProviderId"] = webTokenRequestResult.ResponseData[0].WebAccount.WebAccountProvider.Id;
                ApplicationData.Current.LocalSettings.Values["CurrentUserId"] = webTokenRequestResult.ResponseData[0].WebAccount.Id;
                this.CurrentToken = webTokenRequestResult.ResponseData[0].Token;
                if (signinTask != null)
                {
                    signinTask.SetResult(true);
                }
            }
            else
            {
                if (signinTask != null)
                {
                    signinTask.SetException(new Exception("Not authorized"));
                }
            }

            this.OutputTokenResult(webTokenRequestResult);
            this.LoggedIn?.Invoke(this, null);

        }

        private void OutputTokenResult(WebTokenRequestResult result)
        {
            if (result.ResponseStatus == WebTokenRequestStatus.Success)
            {
                // rootPage.NotifyUser("Web Token request successful for user: " + result.ResponseData[0].WebAccount.UserName, NotifyType.StatusMessage);
                // SignInButton.Content = "Account";
            }
            else
            {
                // rootPage.NotifyUser("Web Token request error: " + result.ResponseError, NotifyType.StatusMessage);
            }
        }

        private void StoreNewAccountDataLocally(WebAccount account)
        {
            if (account.Id != string.Empty)
            {
                ApplicationData.Current.LocalSettings.Values["CurrentUserId"] = account.Id;
            }
            else
            {
                // It's a custom account
                ApplicationData.Current.LocalSettings.Values["CurrentUserId"] = account.UserName;
            }

            ApplicationData.Current.LocalSettings.Values["ProviderID"] = account.WebAccountProvider.Id;
            if (account.WebAccountProvider.Authority != null)
            {
                ApplicationData.Current.LocalSettings.Values["Authority"] = account.WebAccountProvider.Authority;
            }
            else
            {
                ApplicationData.Current.LocalSettings.Values["Authority"] = string.Empty;
            }
        }


    }
}
