//! https://oauth.net/2/

const std = @import("std");
const string = []const u8;
const files = @import("./files.zig");
const pek = @import("pek");
const extras = @import("extras");
const url = @import("url");
const http = @import("http");
const nio = @import("nio");
const json = @import("json");
const builtin = @import("builtin");
const root = @import("root");
const Base = @This();

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

    pub fn real_id(self: Provider) string {
        if (std.mem.indexOfScalar(u8, self.id, ',')) |_| {
            var iter = std.mem.splitScalar(u8, self.id, ',');
            return iter.next().?;
        }
        return self.id;
    }

    pub fn domain(self: Provider) string {
        if (std.mem.indexOfScalar(u8, self.id, ',')) |_| {
            var iter = std.mem.splitScalar(u8, self.id, ',');
            _ = iter.next();
            return iter.next().?;
        }
        return self.id;
    }
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
        .id = "github.com",
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
    pub var railway = Provider{
        .id = "railway",
        .authorize_url = "https://backboard.railway.com/oauth/auth",
        .token_url = "https://backboard.railway.com/oauth/token",
        .me_url = "https://backboard.railway.com/oauth/me",
        .scope = "openid+profile",
        .name_prop = "name",
        .name_prefix = "",
        .logo = icon_url("railway"),
        .color = "#0B0D0E",
    };
};

pub const dynamic_providers = struct {
    pub const _gitea = Provider{
        .id = "gitea",
        .authorize_url = "https://{[domain]s}/login/oauth/authorize",
        .token_url = "https://{[domain]s}/login/oauth/access_token",
        .me_url = "https://{[domain]s}/api/v1/user",
        .name_prop = "username",
        .name_prefix = "@",
        .logo = icon_url("gitea"),
        .color = "#609926",
    };
    pub const _forgejo = Provider{
        .id = "forgejo",
        .authorize_url = "https://{[domain]s}/login/oauth/authorize",
        .token_url = "https://{[domain]s}/login/oauth/access_token",
        .me_url = "https://{[domain]s}/api/v1/user",
        .name_prop = "username",
        .name_prefix = "@",
        .logo = icon_url("forgejo"),
        .color = "#FB923C",
    };
    pub const _gitlab = Provider{
        .id = "gitlab",
        .authorize_url = "https://{[domain]s}/oauth/authorize",
        .token_url = "https://{[domain]s}/oauth/token",
        .me_url = "https://{[domain]s}/api/v4/user",
        .scope = "read_user",
        .name_prop = "username",
        .name_prefix = "@",
        .logo = icon_url("gitlab"),
        .color = "#FCA121",
    };
    pub const _mastodon = Provider{
        .id = "mastodon",
        .authorize_url = "https://{[domain]s}/oauth/authorize",
        .token_url = "https://{[domain]s}/oauth/token",
        .me_url = "https://{[domain]s}/api/v1/accounts/verify_credentials",
        .scope = "read:accounts",
        .name_prop = "username",
        .name_prefix = "@",
        .logo = icon_url("mastodon"),
        .color = "#3088D4",
    };
    pub const _pleroma = Provider{
        .id = "pleroma",
        .authorize_url = "https://{[domain]s}/oauth/authorize",
        .token_url = "https://{[domain]s}/oauth/token",
        .me_url = "https://{[domain]s}/api/v1/accounts/verify_credentials",
        .scope = "read:accounts",
        .name_prop = "username",
        .name_prefix = "@",
        .logo = icon_url("pleroma"),
        .color = "#FBA457",
    };
};

pub fn providerById(alloc: std.mem.Allocator, name: string) !?Provider {
    inline for (comptime std.meta.declarations(providers)) |item| {
        const p = @field(providers, item.name);
        if (std.mem.eql(u8, p.id, name)) {
            return p;
        }
    }
    inline for (comptime extras.globalOption("oauth2_providers", []const Provider) orelse &.{}) |p| {
        if (std.mem.eql(u8, p.id, name)) {
            return p;
        }
    }
    const c_ind = std.mem.indexOfScalar(u8, name, ',') orelse return null;
    const p_id = name[0..c_ind];
    const domain = name[c_ind + 1 ..];
    const args = .{ .domain = domain };
    inline for (comptime std.meta.declarations(dynamic_providers)) |item| {
        const didp = @field(dynamic_providers, item.name);
        if (std.mem.eql(u8, didp.id, p_id)) {
            return Provider{
                .id = name,
                .authorize_url = try nio.fmt.allocPrint(alloc, didp.authorize_url, args),
                .token_url = try nio.fmt.allocPrint(alloc, didp.token_url, args),
                .me_url = try nio.fmt.allocPrint(alloc, didp.me_url, args),
                .scope = didp.scope,
                .name_prop = didp.name_prop,
                .name_prefix = didp.name_prefix,
                .id_prop = didp.id_prop,
                .logo = didp.logo,
                .color = didp.color,
            };
        }
    }
    if (std.mem.eql(u8, p_id, "oidc")) {
        const io = root.io;
        var buf: [4096]u8 = @splat(0);
        var http_client: std.http.Client = .{ .allocator = alloc, .io = io };
        defer http_client.deinit();

        const url_s = try nio.fmt.allocPrint(alloc, "https://{s}/.well-known/openid-configuration", .{domain});
        defer alloc.free(url_s);

        var req = try http_client.request(.GET, try std.Uri.parse(url_s), .{
            .headers = .{
                .accept_encoding = .{ .override = "identity" },
            },
            .redirect_behavior = .not_allowed,
        });
        defer req.deinit();
        try req.sendBodiless();
        var resp = try req.receiveHead(&.{});
        const body_content = try resp.reader(&buf).allocRemaining(alloc, .limited(1024 * 1024 * 5));
        defer alloc.free(body_content);
        if (resp.head.status != .ok) std.log.scoped(.oauth).err("GET '{s}': {d}", .{ url_s, resp.head.status });
        if (resp.head.status != .ok) std.log.scoped(.oauth).err("{s}", .{body_content});
        if (resp.head.status != .ok) return null;
        const val = try json.parseFromSlice(alloc, "body.json", body_content, .{ .maximum_depth = 100, .support_trailing_commas = true });
        defer val.deinit(alloc);
        val.acquire();
        defer val.release();
        const rootobj = val.root.object();
        const authorize_url = rootobj.getS("authorization_endpoint") orelse {
            std.log.scoped(.oauth).err("openid-configuration did not have the expected 'authorization_endpoint' key", .{});
            return null;
        };
        const token_url = rootobj.getS("token_endpoint") orelse {
            std.log.scoped(.oauth).err("openid-configuration did not have the expected 'token_endpoint' key", .{});
            return null;
        };
        const me_url = rootobj.getS("userinfo_endpoint") orelse {
            std.log.scoped(.oauth).err("openid-configuration did not have the expected 'userinfo_endpoint' key", .{});
            return null;
        };
        return Provider{
            .id = name,
            .authorize_url = try alloc.dupe(u8, authorize_url),
            .token_url = try alloc.dupe(u8, token_url),
            .me_url = try alloc.dupe(u8, me_url),
            .scope = "openid",
            .name_prop = "preferred_username",
            .name_prefix = "",
            .id_prop = "sub",
            .logo = icon_url("openid"),
            .color = "#F78C40",
        };
    }
    inline for (comptime extras.globalOption("oauth2_dynamic_providers", []const Provider) orelse &.{}) |didp| {
        if (std.mem.eql(u8, didp.id, p_id)) {
            return Provider{
                .id = name,
                .authorize_url = try nio.fmt.allocPrint(alloc, didp.authorize_url, args),
                .token_url = try nio.fmt.allocPrint(alloc, didp.token_url, args),
                .me_url = try nio.fmt.allocPrint(alloc, didp.me_url, args),
                .scope = didp.scope,
                .name_prop = didp.name_prop,
                .name_prefix = didp.name_prefix,
                .id_prop = didp.id_prop,
                .logo = didp.logo,
                .color = didp.color,
            };
        }
    }
    return null;
}

pub fn clientByProviderId(clients: []const Client, name: string) ?Client {
    for (clients) |item| {
        if (std.mem.eql(u8, name, item.provider.id)) {
            return item;
        }
    }
    return null;
}

pub fn Handlers(comptime T: type) type {
    return struct {
        const Self = @This();
        pub var clients: []Client = &.{};

        pub fn login(request: *http.ServerRequest, body_writer: anytype, alloc: std.mem.Allocator, query: url.SearchParams, request_headers: *const http.HeadersMap, response_status: *http.Status, response_headers: *http.HeadersMap) !void {
            if (query.get("with")) |with| {
                const client = clientByProviderId(Self.clients, with) orelse return try fail(response_status, body_writer, "Client with that ID not found!\n", .{});
                return try loginOne(request, alloc, T, client, T.callbackPath, request_headers, response_status, response_headers);
            }
            if (Self.clients.len == 1) {
                return try loginOne(request, alloc, T, clients[0], T.callbackPath, request_headers, response_status, response_headers);
            }

            try response_headers.append("content-type", "text/html");
            const page = files.@"/selector.pek";
            const tmpl = comptime pek.parse(page);
            try pek.compile(Base, alloc, body_writer, tmpl, .{
                .clients = Self.clients,
            });
        }

        pub fn callback(request: *http.ServerRequest, body_writer: anytype, alloc: std.mem.Allocator, query: url.SearchParams, request_headers: *const http.HeadersMap, response_status: *http.Status, response_headers: *http.HeadersMap) !void {
            _ = request;
            const state = query.get("state") orelse return try fail(response_status, body_writer, "", .{});
            const client = clientByProviderId(Self.clients, state) orelse return try fail(response_status, body_writer, "error: No handler found for provider: {s}\n", .{state});
            const code = query.get("code") orelse return try fail(response_status, body_writer, "", .{});

            const io = if (!builtin.is_test) root.io else std.Options.debug_io;
            var buf: [4096]u8 = @splat(0);
            var http_client: std.http.Client = .{ .allocator = alloc, .io = io };
            defer http_client.deinit();

            var params = url.SearchParams.init(alloc);
            try params.append("client_id", client.id);
            try params.append("client_secret", client.secret);
            try params.append("grant_type", "authorization_code");
            try params.append("code", code);
            try params.append("redirect_uri", try redirectUri(request_headers, alloc, T.callbackPath));
            try params.append("state", "none");
            const req_body = try params.encode();

            var req = try http_client.request(.POST, try std.Uri.parse(client.provider.token_url), .{
                .headers = .{
                    .accept_encoding = .{ .override = "identity" },
                    .authorization = .{ .override = try nio.fmt.allocPrint(alloc, "Basic {s}", .{try extras.base64EncodeAlloc(alloc, try std.mem.join(alloc, ":", &.{ client.id, client.secret }))}) },
                    .content_type = .{ .override = "application/x-www-form-urlencoded" },
                },
                .extra_headers = &.{
                    .{ .name = "Accept", .value = "application/json" },
                },
                .redirect_behavior = .not_allowed,
            });
            defer req.deinit();
            try req.sendBodyComplete(req_body);
            var resp = try req.receiveHead(&.{});
            const body_content = try resp.reader(&buf).allocRemaining(alloc, .limited(1024 * 1024 * 5));
            if (resp.head.status != .ok) std.log.scoped(.oauth).debug("{s}: {s}", .{ @tagName(resp.head.status), body_content });
            if (resp.head.status != .ok) return error.OauthBadToken;
            const val = try json.parseFromSlice(alloc, "body.json", body_content, .{ .maximum_depth = 100, .support_trailing_commas = true });
            val.acquire();
            const tt = val.root.object().getS("token_type").?;
            if (!std.ascii.eqlIgnoreCase(tt, "bearer")) return fail(response_status, body_writer, "oauth2: invalid token type: expected 'bearer', got '{s}'", .{tt});
            const at = val.root.object().getS("access_token") orelse return try fail(response_status, body_writer, "Identity Provider Login Error!\n{s}", .{body_content});
            val.release();

            var req2 = try http_client.request(.GET, try std.Uri.parse(client.provider.me_url), .{
                .headers = .{
                    .accept_encoding = .{ .override = "identity" },
                    .authorization = .{ .override = try nio.fmt.allocPrint(alloc, "Bearer {s}", .{at}) },
                },
                .extra_headers = &.{
                    .{ .name = "Accept", .value = "application/json" },
                },
                .redirect_behavior = .not_allowed,
            });
            defer req2.deinit();
            try req2.sendBodiless();
            var resp2 = try req2.receiveHead(&.{});
            const body_content2 = try resp2.reader(&buf).allocRemaining(alloc, .limited(1024 * 1024 * 5));
            if (resp2.head.status != .ok) std.log.scoped(.oauth).debug("{s}: {s}", .{ @tagName(resp2.head.status), body_content2 });
            if (resp2.head.status != .ok) return error.OauthBadUserinfo;
            const val2 = try json.parseFromSlice(alloc, "body2.json", body_content2, .{ .maximum_depth = 100, .support_trailing_commas = true });
            val2.acquire();
            const id = try fixId(val2.root.object().getAny(client.provider.id_prop).?);
            const name = val2.root.object().getS(client.provider.name_prop).?;
            val2.release();
            try T.saveInfo(response_headers, alloc, client.provider, id, name, val, val2);

            try response_headers.append("location", T.doneUrl);
            response_status.* = .found;
        }
    };
}

fn loginOne(request: *http.ServerRequest, alloc: std.mem.Allocator, comptime T: type, client: Client, callbackPath: string, request_headers: *const http.HeadersMap, response_status: *http.Status, response_headers: *http.HeadersMap) !void {
    if (try T.isLoggedIn(request, alloc)) {
        try response_headers.append("location", T.doneUrl);
    } else {
        const idp = client.provider;
        var params = url.SearchParams.init(alloc);
        try params.append("client_id", client.id);
        try params.append("redirect_uri", try redirectUri(request_headers, alloc, callbackPath));
        try params.append("response_type", "code");
        try params.append("scope", idp.scope);
        try params.append("duration", "temporary");
        try params.append("state", idp.id);
        const authurl = try std.mem.join(alloc, "?", &.{ idp.authorize_url, try params.encode() });
        try response_headers.append("location", authurl);
    }
    response_status.* = .found;
}

fn fail(response_status: *http.Status, body_writer: anytype, comptime err: string, args: anytype) !void {
    response_status.* = .bad_request;
    try body_writer.print(err, args);
}

fn redirectUri(request_headers: *const http.HeadersMap, alloc: std.mem.Allocator, callbackPath: string) !string {
    const xproto = request_headers.find("x-forwarded-proto") orelse "";
    const maybe_tls = std.mem.eql(u8, xproto, "https");
    const proto: string = if (maybe_tls) "https" else "http";
    const host = request_headers.find("host").?;
    return try nio.fmt.allocPrint(alloc, "{s}://{s}{s}", .{ proto, host, callbackPath });
}

fn fixId(id: json.ValueIndex) !string {
    return switch (id.v()) {
        .string => |v| v.to(),
        .number => |v| v.to(),
        else => unreachable,
    };
}

pub fn pek_domain(alloc: std.mem.Allocator, writer: pek.Writer, p: Provider) !void {
    _ = alloc;
    try writer.writeAll(p.domain());
}
