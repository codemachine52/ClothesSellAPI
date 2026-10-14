namespace ClothesSell
{
    public record OrderItemDto(int ClothesSizeID, int Count);
    public record CreateOrderRequest(List<OrderItemDto> Items);
}
