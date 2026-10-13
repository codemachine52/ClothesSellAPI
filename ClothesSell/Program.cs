using ClothesSell.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<MG_PR3Context>();

var app = builder.Build();

app.MapGet("/api/clothes", (MG_PR3Context context) => Results.Json(context.Clothes));

app.Run();