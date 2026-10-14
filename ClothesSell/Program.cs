using ClothesSell;
using ClothesSell.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json.Serialization;
var builder = WebApplication.CreateBuilder(args);
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
});

builder.Services.AddDbContext<MG_PR3Context>();
var jwtKey = builder.Configuration["Jwt:Key"]!;
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
string GenerateToken(User user)
{
    var claims = new[]
    {
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
        new Claim(ClaimTypes.Name, user.Login),
        new Claim(ClaimTypes.Role, user.Role?.Name ?? "Клиент")
    };

    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken(
        issuer: builder.Configuration["Jwt:Issuer"],
        audience: builder.Configuration["Jwt:Audience"],
        claims: claims,
        expires: DateTime.UtcNow.AddHours(8),
        signingCredentials: creds);

    return new JwtSecurityTokenHandler().WriteToken(token);
}

int GetUserId(ClaimsPrincipal p) =>
    int.Parse(p.FindFirstValue(ClaimTypes.NameIdentifier)!);

app.MapPost("/api/auth/register", async (RegisterReq req, MG_PR3Context db) =>
{
    if (await db.Users.AnyAsync(u => u.Login == req.Login))
        return Results.BadRequest("Логин занят");

    var clientRole = await db.Roles.FirstOrDefaultAsync(r => r.Name == "Клиент");
    if (clientRole == null)
        return Results.Problem("Роль 'Клиент' не найдена в БД");

    var user = new User
    {
        Name = req.Name,
        PhoneNumber = req.PhoneNumber,
        Login = req.Login,
        Address = req.Address,
        Password = BCrypt.Net.BCrypt.HashPassword(req.Password), 
        RoleId = clientRole.Id
    };

    db.Users.Add(user);
    await db.SaveChangesAsync();

    return Results.Ok("Пользователь зарегистрирован");
});

app.MapPost("/api/auth/login", async (LoginReq req, MG_PR3Context db) =>
{
    var user = await db.Users
        .Include(u => u.Role)
        .FirstOrDefaultAsync(u => u.Login == req.Login);

    if (user == null)
        return Results.Unauthorized();
    if (!BCrypt.Net.BCrypt.Verify(req.Password, user.Password))
        return Results.Unauthorized();

    var token = GenerateToken(user);
    return Results.Json(new AuthResponse(token, user.Role?.Name ?? "Клиент"));
});

app.MapGet("/api/clothes", async (MG_PR3Context context) => Results.Json(await context.Clothes.AsNoTracking().ToListAsync()));


app.MapGet("/api/clothes/search", async (string q, MG_PR3Context db) =>
{
    if (string.IsNullOrWhiteSpace(q))
        return Results.BadRequest("Параметр 'q' обязателен и не может быть пустым");

    var list = await db.Clothes
        .Where(c => c.Name.Contains(q))
        .AsNoTracking()
        .ToListAsync();

    return Results.Ok(list);
})
.WithTags("Clothes")
.WithSummary("Поиск одежды по части названия (публично)");

app.MapPost("/api/orders", [Authorize]
async (
    CreateOrderRequest req,
    MG_PR3Context db,
    ClaimsPrincipal user) =>
{
    if (req.Items == null || req.Items.Count == 0)
        return Results.BadRequest("Список товаров пуст");
    var userId = GetUserId(user); //получаем id user из jwt

    // 3. Проверяем каждый размер: существует и хватает ли на складе
    foreach (var item in req.Items)
    {
        if (item.Count <= 0)
            return Results.BadRequest($"Некорректное количество для ClothesSize {item.ClothesSizeID}");

        var cs = await db.ClothesSizes.FindAsync(item.ClothesSizeID);
        if (cs == null)
            return Results.BadRequest($"Размер товара с ID {item.ClothesSizeID} не найден");

        if (cs.CountClothes < item.Count)
            return Results.BadRequest(
                $"Недостаточно товара для ClothesSize {item.ClothesSizeID}: " +
                $"в наличии {cs.CountClothes}, запрошено {item.Count}");
    }
    var newStatus = await db.OrderStatuses
        .FirstOrDefaultAsync(s => s.StatusName == "Новый");

    if (newStatus == null)
        return Results.Problem("Статус 'Новый' отсутствует в БД");

    var order = new Order
    {
        CreateDate = DateTime.Now,
        CurrentStatusId = newStatus.Id,
        UserId = userId
    };

    db.Orders.Add(order);
    await db.SaveChangesAsync(); // нужен ID заказа

    foreach (var item in req.Items)
    {
        db.OrderClothes.Add(new OrderClothe
        {
            OrderId = order.Id,
            ClothesSizeId = item.ClothesSizeID,
            Count = item.Count
        });
    }
    await db.SaveChangesAsync();

    return Results.Ok(new
    {
        orderId = order.Id,
        createDate = order.CreateDate,
        status = newStatus.StatusName,
        items = req.Items.Count
    });
})
.WithTags("Orders")
.WithSummary("Создать новый заказ (только авторизованный пользователь)");
app.Run();