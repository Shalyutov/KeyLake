using KeyLake;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);

string issuer = builder.Configuration["Issuer"] ?? "";
string audience = builder.Configuration["Audience"] ?? "";

if (!Directory.Exists("keys")) Directory.CreateDirectory("keys");

SymmetricSecurityKey key;
if (File.Exists("issuer.key"))
{
    key = new SymmetricSecurityKey(File.ReadAllBytes("issuer.key"));
}
else
{
    byte[] payload = CryptoIO.CreateRandBytes(32);
    File.WriteAllBytes("issuer.key", payload);
    key = new SymmetricSecurityKey(payload);
}

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme,
        options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters()
            {
                ValidateIssuer = true,
                ValidIssuer = issuer,
                ValidateAudience = true,
                ValidAudience = audience,
                ValidateLifetime = true,
                IssuerSigningKey = key,
                ValidateIssuerSigningKey = true
            };
        });
builder.Services.AddAuthorization();
builder.Services.AddAuthorizationBuilder()
  .AddPolicy("federation", policy =>
        policy
            .RequireClaim(ClaimTypes.NameIdentifier, "federation"));

var app = builder.Build();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/key/{id}", async (string id) =>
{
    if (File.Exists($"keys/{id}.key"))
    {
        SymmetricSecurityKey key = await CryptoIO.GetKey(id);
        return Results.Ok(Convert.ToBase64String(key.Key));
    }
    else
    {
        return Results.BadRequest();
        
    }
}).RequireAuthorization("federation");
app.MapPost("/key/{id}", async (string id) =>
{
    if (!File.Exists($"keys/{id}.key"))
    {
        try
        {
            byte[] payload = CryptoIO.CreateRandBytes(32);
            SymmetricSecurityKey key = await CryptoIO.CreateKey(id, payload);
            return Results.Ok(Convert.ToBase64String(payload));
        }
        catch
        {
            return Results.Problem("Возникла ошибка при обработке запроса на сервере");
        }
    }
    else
    {
        return Results.BadRequest();
    }
}).RequireAuthorization("federation");
app.MapDelete("/key/{id}", (string id) =>
{
    if (CryptoIO.DeleteKey(id))
    {
        return Results.Accepted();
    }
    else
    {
        return Results.Problem("Возникла ошибка при обработке запроса на сервере");
    }
}).RequireAuthorization("federation");

//Emergency endpoints
app.MapGet("/clear", () =>
{
    Directory.Delete("keys", true);
}).RequireAuthorization("federation");
app.MapGet("/alert", () =>
{
    Directory.Delete("keys", true);
    File.Delete("issuer.key");
}).RequireAuthorization("federation");

app.MapGet("/access", () => {
    if (app.Environment.IsDevelopment())
    {
        var now = DateTime.UtcNow;
        var jwt = new JwtSecurityToken(
            issuer,
            audience,
            new List<Claim>() { new Claim(ClaimTypes.NameIdentifier, "federation")},
            now,
            now.Add(TimeSpan.FromMinutes(10)),
            new SigningCredentials(key, SecurityAlgorithms.HmacSha256));
        var token = new JwtSecurityTokenHandler().WriteToken(jwt);
        return Results.Ok(token);
    }
    else
    {
        return Results.BadRequest();
    }
});

app.Run();
