using System.Net;
using Newtonsoft.Json;

namespace OtpApiService.Model
{
    public class StatusMessage
    {
        public HttpStatusCode StatusCode { get; set; }
        [JsonIgnore]
        public MessageType MessageType { get; set; }
        [JsonProperty(PropertyName = "message")]
        public string Message { get; set; }
        [JsonIgnore]
        public bool Status { get; set; }
    }

    public enum MessageType
    {
        Error,
        Info,
        Warning,
        Success
    }
}
