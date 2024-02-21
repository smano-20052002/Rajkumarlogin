using System.ComponentModel.DataAnnotations;

namespace LoginRoleBasedAuthenticationDemo.ViewModel
{
    public class UpdatePermission
    {
        [Required(ErrorMessage = "UserName is required")]
        public string Email { get; set; }
       
      
    }
}
