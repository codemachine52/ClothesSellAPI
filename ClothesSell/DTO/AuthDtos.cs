namespace ClothesSell
{
    public record LoginReq(string Login, string Password);
    public record RegisterReq(string Name, string PhoneNumber, string Login, string Address, string Password);
    public record AuthResponse(string Token, string Role);
}
