namespace AngularAuthAPI.DTO
{
    public partial class TokenApiDto
    {
        public string RefreshToken { get; set; } = string.Empty;
        public string AccessToken { get; set; } = string.Empty;
    }
}
