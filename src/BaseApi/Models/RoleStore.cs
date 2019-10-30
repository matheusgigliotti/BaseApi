using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BaseApi.Models
{
    public class RoleStore
    {
        public const string COMMA = ",";
        public const string ADMINISTRADOR = "ADMINISTRADOR";

        public int Id { get; set; }
        public string RoleName { get; set; }
        public string RoleNameNormalized { get; set; }
    }
}
