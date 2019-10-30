using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BaseApi.Models
{
    public class User
    {
        public string Email { get; set; }
        public string Nome { get; set; }
        public string Sobrenome { get; set; }
        public string Password { get; set; }
        public bool LoginAutomatico { get; set; }
    }
}
