using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace OtpApiService.Model
{
    public class ContactVerification
    {
        [Required]
        public string OtpCode { get; set; }
        [Required]
        public string Mobile { get; set; }
        //[JsonRequired]
        public string CSRFToken { get; set; }
    }

    public class OtpRequest
    {
        [Required(ErrorMessage = "Mobile number is required.")]
        public string Mobile { get; set; }
        [NotMapped]
        public bool FromPortal { get; set; }
    }
}
