using Com.DataSoft.EKYC.Common.Utility;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using OtpApiService.Model;
using StackExchange.Redis;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mime;
using System.Threading.Tasks;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace OtpApiService.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CacheController : ControllerBase
    {
        private readonly IDatabase _database;
        public CacheController(IDatabase database)
        {
            _database = database;
        }


        [HttpPost("send-otp")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(StatusMessage), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(StatusMessage), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(String), StatusCodes.Status415UnsupportedMediaType)]
        [ProducesResponseType(typeof(String), StatusCodes.Status500InternalServerError)]
        [Consumes(MediaTypeNames.Application.Json)]
        [ApiExplorerSettings(IgnoreApi = false)]
        [AllowAnonymous]
        public async Task<IActionResult> SendOtp(OtpRequest otpRequest)
        {
            try
            {
                Random r = new Random();
                var range = r.Next(0, 1000000);
                string otp = range.ToString("000000");
                string hash = EncryptionUtil.Md5Hash(otp);
                _database.StringSet(otpRequest.Mobile, hash, TimeSpan.FromMinutes(15));
                return Ok(new StatusMessage { StatusCode = HttpStatusCode.OK, Message = "OTP Sended successfully. "+otp });
            }
            catch(Exception e)
            {
                return BadRequest(new StatusMessage { StatusCode = HttpStatusCode.BadRequest, Message = e.InnerException!=null ? e.InnerException.Message : e.Message });
            }
        }

        [HttpPost("verify-otp")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(StatusMessage), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(StatusMessage), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(String), StatusCodes.Status415UnsupportedMediaType)]
        [ProducesResponseType(typeof(String), StatusCodes.Status500InternalServerError)]
        [Consumes(MediaTypeNames.Application.Json)]
        [ApiExplorerSettings(IgnoreApi = false)]
        [AllowAnonymous]
        public async Task<IActionResult> VerifyOtp([FromBody]ContactVerification verify)
        {
            try
            {
                var data = _database.StringGet(verify.Mobile);

                if (data.HasValue)
                {
                    if (EncryptionUtil.Md5Hash(verify.OtpCode).Equals(data))
                    {
                        _database.KeyDelete(verify.Mobile);

                        return Ok(new StatusMessage { StatusCode = HttpStatusCode.OK, Message = "OTP Verified Successfully." });
                    }
                    else
                    {
                        return Ok(new StatusMessage { StatusCode = HttpStatusCode.OK, Message = "Invalid OTP Code." });
                    }
                    
                }
                return Ok(new StatusMessage { StatusCode = HttpStatusCode.OK, Message = "No Data Found." });
            }
            catch(Exception e)
            {
                return BadRequest(new StatusMessage { StatusCode = HttpStatusCode.BadRequest, Message = e.InnerException != null ? e.InnerException.Message : e.Message });
            }
           
        }

    }
}
