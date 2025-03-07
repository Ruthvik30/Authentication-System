using Microsoft.AspNetCore.Mvc;

namespace AngularAuthAPI.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class HomeController : ControllerBase
    {
        [HttpGet]
        public IActionResult Index()
        {
            //if (Request.Headers.ContainsKey("X-Custom-Header"))
            //{
            //    return Content("<h1>Header exists!</h1>");
            //}
            //else
            //{
            //    return NotFound("Not found!");
            //}

            string filePath = @"C:\Users\pruthvik\Downloads\qbuserapi.json";
            using (StreamReader reader = new StreamReader(filePath))
            {
                string data = reader.ReadToEnd();
                var dat = System.Text.Json.JsonSerializer.Deserialize<UserData>(data);
            }
            
            return Ok();
        }
    }

    public class ResponseUser
    {
        public int uid { get; set; }
        public string hashId { get; set; }
        public string firstName { get; set; }
        public string lastName { get; set; }
        public string email { get; set; }
        public string userName { get; set; }
        public DateTime lastAccess { get; set; }
        public string lastAccessFormatted { get; set; }
        public bool isActive { get; set; }
        public int numGroupsMember { get; set; }
        public int numGroupsManaged { get; set; }
        public bool hasAppAccess { get; set; }
        public int numAppsManaged { get; set; }
        public bool canCreateAppsFromGlobal { get; set; }
        public bool isInCompany { get; set; }
        public bool isDenied { get; set; }
        public bool isRealmApproved { get; set; }
        public bool isServiceAccount { get; set; }
        public bool isGuest { get; set; }
        public bool isDeniedDueToLdap { get; set; }
        public bool isRealmAdmin { get; set; }
        public bool isDeactivated { get; set; }
        public bool isQuickbaseEmployeeEmailDomain { get; set; }
        public bool isQuickBaseStaff { get; set; }
        public bool isPaidSeat { get; set; }
        public bool isAccountAdminFull { get; set; }
        public bool isAccountAdminSupport { get; set; }
        public bool isSuperUser { get; set; }
        public bool canReceiveSecurityQAResetRequests { get; set; }
        public bool canCreateAppsFromDirect { get; set; }
        public bool canCreateAppsFromGroup { get; set; }
        public bool canCreateAppsFromDomGroup { get; set; }
        public bool canCreateApps { get; set; }
        public string SSOUniqueID { get; set; }
        public string SCIMUsername { get; set; }
        public bool isVerified { get; set; }
        public bool isRegistered { get; set; }
        public bool overrideSSODefault { get; set; }
        public string userRegistrationStatus { get; set; }
        public bool inRealmDirectory { get; set; }
        public bool isNonPending { get; set; }
        public object serviceAccountTrustees { get; set; } // Use object or a specific type if known
    }

    public class UserData
    {
        public string errorCode { get; set; }
        public string errorMessage { get; set; }
        public List<ResponseUser> data { get; set; }
    }
}
