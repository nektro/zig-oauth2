// https://oauth.net/2/
//
const std = @import("std");
const string = []const u8;

pub const Provider = struct {
    id: string,
    authorize_url: string,
    token_url: string,
    me_url: string,
    scope: string = "",
    name_prop: string,
    name_prefix: string = "",
    id_prop: string = "id",
    logo: string,
    color: string,
};

pub const Client = struct {
    provider: Provider,
    id: string,
    secret: string,
};

fn icon_url(comptime name: string) string {
    return "https://unpkg.com/simple-icons@" ++ "5.13.0" ++ "/icons/" ++ name ++ ".svg";
}

pub const providers = struct {
    pub var amazon = Provider{
        .id = "amazon",
        .authorize_url = "https://www.amazon.com/ap/oa",
        .token_url = "https://api.amazon.com/auth/o2/token",
        .me_url = "https://api.amazon.com/user/profile",
        .scope = "profile",
        .name_prop = "name",
        .id_prop = "user_id",
        .logo = icon_url("amazon"),
        .color = "#FF9900",
    };
    pub var battle_net = Provider{
        .id = "battle.net",
        .authorize_url = "https://us.battle.net/oauth/authorize",
        .token_url = "https://us.battle.net/oauth/token",
        .me_url = "https://us.battle.net/oauth/userinfo",
        .scope = "openid",
        .name_prop = "battletag",
        .logo = icon_url("battle-dot-net"),
        .color = "#00AEFF",
    };
    pub var discord = Provider{
        .id = "discord",
        .authorize_url = "https://discordapp.com/api/oauth2/authorize",
        .token_url = "https://discordapp.com/api/oauth2/token",
        .me_url = "https://discordapp.com/api/users/@me",
        .scope = "identify",
        .name_prop = "username",
        .name_prefix = "@",
        .logo = icon_url("discord"),
        .color = "#7289DA",
    };
    pub var facebook = Provider{
        .id = "facebook",
        .authorize_url = "https://graph.facebook.com/oauth/authorize",
        .token_url = "https://graph.facebook.com/oauth/access_token",
        .me_url = "https://graph.facebook.com/me",
        .name_prop = "name",
        .logo = icon_url("facebook"),
        .color = "#1877F2",
    };
    pub var github = Provider{
        .id = "github",
        .authorize_url = "https://github.com/login/oauth/authorize",
        .token_url = "https://github.com/login/oauth/access_token",
        .me_url = "https://api.github.com/user",
        .scope = "read:user",
        .name_prop = "login",
        .name_prefix = "@",
        .logo = icon_url("github"),
        .color = "#181717",
    };
    pub var google = Provider{
        .id = "google",
        .authorize_url = "https://accounts.google.com/o/oauth2/v2/auth",
        .token_url = "https://www.googleapis.com/oauth2/v4/token",
        .me_url = "https://www.googleapis.com/oauth2/v1/userinfo?alt=json",
        .scope = "profile",
        .name_prop = "name",
        .logo = icon_url("google"),
        .color = "#4285F4",
    };
    pub var microsoft = Provider{
        .id = "microsoft",
        .authorize_url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        .token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        .me_url = "https://graph.microsoft.com/v1.0/me/",
        .scope = "https://graph.microsoft.com/user.read",
        .name_prop = "displayName",
        .logo = icon_url("microsoft"),
        .color = "#666666",
    };
    pub var reddit = Provider{
        .id = "reddit",
        .authorize_url = "https://old.reddit.com/api/v1/authorize",
        .token_url = "https://old.reddit.com/api/v1/access_token",
        .me_url = "https://oauth.reddit.com/api/v1/me",
        .scope = "identity",
        .name_prop = "name",
        .name_prefix = "u/",
        .logo = icon_url("reddit"),
        .color = "#FF4500",
    };
};

pub const dynamic_providers = struct {
    pub var _gitea = Provider{
        .id = "_gitea",
        .authorize_url = "https://{domain}/login/oauth/authorize",
        .token_url = "https://{domain}/login/oauth/access_token",
        .me_url = "https://{domain}/api/v1/user",
        .name_prop = "username",
        .name_prefix = "@",
        .logo = icon_url("gitea"),
        .color = "#609926",
    };
    pub var _gitlab = Provider{
        .id = "_gitlab",
        .authorize_url = "https://{domain}/oauth/authorize",
        .token_url = "https://{domain}/oauth/token",
        .me_url = "https://{domain}/api/v4/user",
        .scope = "read_user",
        .name_prop = "username",
        .name_prefix = "@",
        .logo = icon_url("gitlab"),
        .color = "#FCA121",
    };
    pub var _mastodon = Provider{
        .id = "_mastodon",
        .authorize_url = "https://{domain}/oauth/authorize",
        .token_url = "https://{domain}/oauth/token",
        .me_url = "https://{domain}/api/v1/accounts/verify_credentials",
        .scope = "read:accounts",
        .name_prop = "username",
        .name_prefix = "@",
        .logo = icon_url("mastodon"),
        .color = "#3088D4",
    };
    pub var _pleroma = Provider{
        .id = "_pleroma",
        .authorize_url = "https://{domain}/oauth/authorize",
        .token_url = "https://{domain}/oauth/token",
        .me_url = "https://{domain}/api/v1/accounts/verify_credentials",
        .scope = "read:accounts",
        .name_prop = "username",
        .name_prefix = "@",
        .logo = icon_url("pleroma"),
        .color = "#FBA457",
    };
};
