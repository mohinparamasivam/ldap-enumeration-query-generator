// To change the tabs for Simple, Advance and NSE mode
function ChangeTab(evt, customTab) {
  var i, tabcontent, tablinks;

  tabcontent = document.getElementsByClassName("tabcontent");
  for (i = 0; i < tabcontent.length; i++) {
    tabcontent[i].style.display = "none";
  }

  tablinks = document.getElementsByClassName("tablinks");
  for (i = 0; i < tablinks.length; i++) {
    tablinks[i].className = tablinks[i].className.replace(" active", "");
  }

  document.getElementById(customTab).style.display = "block";
  evt.currentTarget.className += " active";
}

// To set Nmap Command 
function SetLDAP() {
  // Variable Declaration
  // IP address
  var ip = document.getElementById("LDAP_IP").value;
  var port = document.getElementById("LDAP_PORT").value;
  var domain = document.getElementById("Domain").value; //use this for ADSearch


  //Break Domain into  parts for LDAPSearch.
  var domain_array = domain.split(".")

 //Find length of array if subdomain involved. Need 3 parts

 if (domain_array.length===3){
  var domain_part1 = domain_array[0];
  var domain_part2 = domain_array[1];
  var domain_part3 = domain_array[2];
 }

 else if (domain_array.length===2){
  var domain_part1 = domain_array[0];
  var domain_part2 = domain_array[1];
 }
 
  // PreBuilt-Query Mode
  var PreBuiltMode = document.getElementById("PreBuilt-Mode");

  //Set the ADSearch , LDAPSearch and Raw LDAP Query Value


  // IF Statement if domain has 3 parts

  if (domain_array.length===3){

    //Find All Domain Users
    if (PreBuiltMode.value === "Find all Domain Users") {
      ldap_query = "(&(objectCategory=user)(objectClass=user))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }

    else if (PreBuiltMode.value === "Find all Domain Admins") {
      ldap_query = "(&(objectClass=user)(objectCategory=person)(memberOf=CN=Domain Admins,CN=Users,DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find all Domain Groups") {
      ldap_query = "(&(objectClass=group)(objectCategory=group))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find Domain Groups ending with 'admin' keyword") {
      ldap_query_adsearch = "(&(objectClass=group)(objectCategory=group)(name=*admin))";
      ldap_query_ldapsearch = "(&(objectClass=group)(cn=*admin))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query_adsearch+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query_ldapsearch+"\"";
      var RAW_Command = ldap_query_adsearch;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find Domain Users with password never expires enabled") {
      ldap_query = "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=65536))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find Domain Controllers") {
      ldap_query = "(&(objectClass=computer)(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find Domain Computers") {
      ldap_query = "(&(objectClass=computer)(objectCategory=computer))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find Decoy HoneyPot Accounts") {
      ldap_query = "(&(objectClass=user)(objectCategory=person)(logonCount=0)(badPwdCount=0))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find Default User Accounts with password in Description") {
      ldap_query = "(&(objectClass=user)(objectCategory=person)(description=*password*))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Map Domain Trusts") {
      ldap_query = "(&(objectClass=trustedDomain)(objectCategory=trustedDomain))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find Principals with DCSync Rights") {
      ldap_query = "(&(objectClass=user)(objectCategory=person)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "List all Kerberoastable Accounts") {
      ldap_query = "(&(objectCategory=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find AS-REP Roastable Accounts (DontReqPreAuth)") {
      ldap_query = "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find UnConstrained Delegation Enabled Workstations") {
      ldap_query = "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(userAccountControl:1.2.840.113556.1.4.803:=524288))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find Constrained Delegation Enabled Workstations") {
      ldap_query = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find Interesting ACL") {
      ldap_query_adsearch = "(&(|(ActiveDirectoryRights=GenericAll)(ActiveDirectoryRights=Write)(ActiveDirectoryRights=Create)(ActiveDirectoryRights=Delete)(ActiveDirectoryRights=ExtendedRight))(&(AceQualifier=Allow)(SecurityIdentifier=^S-1-5-.*-[1-9]\\d{3,}$)))";
      ldap_query_ldapsearch = "(|(ActiveDirectoryRights=GenericAll)(ActiveDirectoryRights=Write)(ActiveDirectoryRights=Create)(ActiveDirectoryRights=Delete)(ActiveDirectoryRights=ExtendedRight))(&(AceQualifier=Allow)(SecurityIdentifier=^S-1-5-.*-[1-9]\\d{3,}$))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query_adsearch+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query_ldapsearch+"\"";
      var RAW_Command = ldap_query_adsearch;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find Workstations where Domain Users can RDP") {
      ldap_query = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=4096))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find LAPS Enabled Workstations") {
      ldap_query = "(&(objectCategory=computer)(ms-Mcs-AdmPwdExpirationTime=*))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }
  }


  // IF Statement if domain has 2 parts

  else if (domain_array.length===2){

    //Find All Domain Users
    if (PreBuiltMode.value === "Find all Domain Users") {
      ldap_query = "(&(objectCategory=user)(objectClass=user))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }

    else if (PreBuiltMode.value === "Find all Domain Admins") {
      ldap_query = "(&(objectClass=user)(objectCategory=person)(memberOf=CN=Domain Admins,CN=Users,DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find all Domain Groups") {
      ldap_query = "(&(objectClass=group)(objectCategory=group))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find Domain Groups ending with 'admin' keyword") {
      ldap_query_adsearch = "(&(objectClass=group)(objectCategory=group)(name=*admin))";
      ldap_query_ldapsearch = "(&(objectClass=group)(cn=*admin))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query_adsearch+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query_ldapsearch+"\"";
      var RAW_Command = ldap_query_adsearch;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find Domain Users with password never expires enabled") {
      ldap_query = "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=65536))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find Domain Controllers") {
      ldap_query = "(&(objectClass=computer)(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find Domain Computers") {
      ldap_query = "(&(objectClass=computer)(objectCategory=computer))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find Decoy HoneyPot Accounts") {
      ldap_query = "(&(objectClass=user)(objectCategory=person)(logonCount=0)(badPwdCount=0))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find Default User Accounts with password in Description") {
      ldap_query = "(&(objectClass=user)(objectCategory=person)(description=*password*))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Map Domain Trusts") {
      ldap_query = "(&(objectClass=trustedDomain)(objectCategory=trustedDomain))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find Principals with DCSync Rights") {
      ldap_query = "(&(objectClass=user)(objectCategory=person)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "List all Kerberoastable Accounts") {
      ldap_query = "(&(objectCategory=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find AS-REP Roastable Accounts (DontReqPreAuth)") {
      ldap_query = "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find UnConstrained Delegation Enabled Workstations") {
      ldap_query = "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(userAccountControl:1.2.840.113556.1.4.803:=524288))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find Constrained Delegation Enabled Workstations") {
      ldap_query = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find Interesting ACL") {
      ldap_query_adsearch = "(&(|(ActiveDirectoryRights=GenericAll)(ActiveDirectoryRights=Write)(ActiveDirectoryRights=Create)(ActiveDirectoryRights=Delete)(ActiveDirectoryRights=ExtendedRight))(&(AceQualifier=Allow)(SecurityIdentifier=^S-1-5-.*-[1-9]\\d{3,}$)))";
      ldap_query_ldapsearch = "(|(ActiveDirectoryRights=GenericAll)(ActiveDirectoryRights=Write)(ActiveDirectoryRights=Create)(ActiveDirectoryRights=Delete)(ActiveDirectoryRights=ExtendedRight))(&(AceQualifier=Allow)(SecurityIdentifier=^S-1-5-.*-[1-9]\\d{3,}$))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query_adsearch+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query_ldapsearch+"\"";
      var RAW_Command = ldap_query_adsearch;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find Workstations where Domain Users can RDP") {
      ldap_query = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=4096))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }


    else if (PreBuiltMode.value === "Find LAPS Enabled Workstations") {
      ldap_query = "(&(objectCategory=computer)(ms-Mcs-AdmPwdExpirationTime=*))";
      var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+ldap_query+"\"";
      var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+ldap_query+"\"";
      var RAW_Command = ldap_query;

      document.getElementById("ADSearch_Command").value = ADSearch_Command;
      document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
      document.getElementById("RAW_Command").value = RAW_Command;
    }
  }
}



//MOHIN EDIT HERE 


// Copy button and the feedback
function CopyToClip(event) {
  var buttonid = event.target.getAttribute("data-id");
  var copyText = document.getElementById(buttonid);
  navigator.clipboard.writeText(copyText.value);

  var comment = event.target.querySelector(".commenttext");
  comment.innerHTML = "Copied!";

}

// Copy button feedback reset
function ResetToClip(event) {
  var comment = event.target.querySelector(".commenttext");
  comment.innerHTML = "Copy to Clipboard";
}

//Disable and enable input
function DisableEnableInput() {

  // Port Number input
  if (document.getElementById("Nmap-Custom-Port").checked) {
    document.getElementById("Port-Number").disabled = false;
  } else {
    document.getElementById("Port-Number").value = "";
    document.getElementById("Port-Number").disabled = true;
  }

  // Exclude Port Number input
  if (document.getElementById("Nmap-Exclude-Port").checked) {
    document.getElementById("Exclude-Port-Number").disabled = false;
  } else {
    document.getElementById("Exclude-Port-Number").value = "";
    document.getElementById("Exclude-Port-Number").disabled = true;
  }

  // Output Name input
  if (document.getElementById("Nmap-DOutput").checked) {
    document.getElementById("Output-Name").disabled = true;
    document.getElementById("Output-Name").value = "";
  } else {
    document.getElementById("Output-Name").disabled = false;
  }

  // Specific NSE Form select
  if (document.getElementById("NSE-Category").value === "specific") {
    document.getElementById("NSE-Specific").disabled = false;
  } else {
    document.getElementById("NSE-Specific").disabled = true;
    document.getElementById("NSE-Specific").value = "";
  }
  // NSE Port input
  if (document.getElementById("NSE-Port").checked) {
    document.getElementById("NSE-Port-Number").disabled = false;
  } else {
    document.getElementById("NSE-Port-Number").value = "";
    document.getElementById("NSE-Port-Number").disabled = true;
  }
}

// to set the category nse option into the form select
function BuiltInQueries() {

  var domain = document.getElementById("Domain").value; 
  //Break Domain into  parts 
  var domain_array = domain.split(".");
  var domain_part1 = domain_array[0];
  var domain_part2 = domain_array[1];
  var domain_part3 = domain_array[2];



  var options = [
    { value: "", text: "Please Select" },
    { value: "Find all Domain Users", text: "Find all Domain Users" },
    { value: "Find all Domain Admins", text: "Find all Domain Admins" },
    { value: "Find all Domain Groups", text: "Find all Domain Groups" },
    { value: "Find Domain Groups ending with 'admin' keyword", text: "Find Domain Groups ending with 'admin' keyword" },
    { value: "Find Domain Users with password never expires enabled", text: "Find Domain Users with password never expires enabled" },
    { value: "Find Domain Controllers", text: "Find Domain Controllers" },
    { value: "Find Domain Computers", text: "Find Domain Computers" },
    { value: "Find Decoy HoneyPot Accounts", text: "Find Decoy HoneyPot Accounts" },
    { value: "Find Default User Accounts with password in Description", text: "Find Default User Accounts with password in Description" },
    { value: "Map Domain Trusts", text: "Map Domain Trusts" },
    { value: "Find Principals with DCSync Rights", text: "Find Principals with DCSync Rights" },
    { value: "List all Kerberoastable Accounts", text: "List all Kerberoastable Accounts" },
    { value: "Find AS-REP Roastable Accounts (DontReqPreAuth)", text: "Find AS-REP Roastable Accounts (DontReqPreAuth)" },
    { value: "Find UnConstrained Delegation Enabled Workstations", text: "Find UnConstrained Delegation Enabled Workstations" },
    { value: "Find Constrained Delegation Enabled Workstations", text: "Find Constrained Delegation Enabled Workstations" },
    { value: "Find Interesting ACL", text: "Find Interesting ACL" },
    { value: "Find Workstations where Domain Users can RDP", text: "Find Workstations where Domain Users can RDP" },
    { value: "Find LAPS Enabled Workstations", text: "Find LAPS Enabled Workstations" }
  ];



  var PreBuiltQuery = document.getElementById("PreBuilt-Mode");

  populateDropdownOptions(PreBuiltQuery, options);
  PreBuiltQuery.value = "Please Select";

  PreBuiltQuery.addEventListener("change", SetLDAP);

}


// Populate dropdown option for the condition
function ConditionOptions(value) {
  var conditionOptions = [
    { value: "", text: "Please Select" },
    { value: "AND", text: "AND" },
    { value: "OR", text: "OR" }
  ];

  if (value === 1) {
    //clear all the dropdown value before populating
    var Condition1Option = document.getElementById("Condition1");
    var Condition2Option = document.getElementById("Condition2");
    var Condition3Option = document.getElementById("Condition3");

    populateDropdownOptions(Condition1Option, [],true);
    populateDropdownOptions(Condition2Option, [],true);
    populateDropdownOptions(Condition3Option, [],true);


    //Populate with the dropdown options
    populateDropdownOptions(Condition1Option, conditionOptions);
    populateDropdownOptions(Condition2Option, conditionOptions);
    populateDropdownOptions(Condition3Option, conditionOptions);


    Condition1Option.value = ""; // Set the initial selected option to empty value
    Condition1Option.classList.add("centered-option"); // Add CSS class to center the selected option
  } 

  else if (value === 2) {

    var Condition1Option = document.getElementById("Condition1");
    var Condition2Option = document.getElementById("Condition2");
    var Condition3Option = document.getElementById("Condition3");

    populateDropdownOptions(Condition1Option, [],true);
    populateDropdownOptions(Condition2Option, [],true);
    populateDropdownOptions(Condition3Option, [],true);

    //Populate with the dropdown options
    populateDropdownOptions(Condition1Option, conditionOptions);
    populateDropdownOptions(Condition2Option, conditionOptions);
    populateDropdownOptions(Condition3Option, conditionOptions);
    

    Condition1Option.value = ""; // Set the initial selected option to empty value
    Condition2Option.value = "";
    Condition1Option.classList.add("centered-option"); // Add CSS class to center the selected option
    Condition2Option.classList.add("centered-option"); // Add CSS class to center the selected option
  } 

  else if (value === 3) {
    
    var Condition1Option = document.getElementById("Condition1");
    var Condition2Option = document.getElementById("Condition2");
    var Condition3Option = document.getElementById("Condition3");

    populateDropdownOptions(Condition1Option, [],true);
    populateDropdownOptions(Condition2Option, [],true);
    populateDropdownOptions(Condition3Option, [],true);

    //Populate with the dropdown options
    populateDropdownOptions(Condition1Option, conditionOptions);
    populateDropdownOptions(Condition2Option, conditionOptions);
    populateDropdownOptions(Condition3Option, conditionOptions);

    Condition1Option.value = ""; // Set the initial selected option to empty value
    Condition2Option.value = "";
    Condition3Option.value = "";
    Condition1Option.classList.add("centered-option"); // Add CSS class to center the selected option
    Condition2Option.classList.add("centered-option"); // Add CSS class to center the selected option
    Condition3Option.classList.add("centered-option"); // Add CSS class to center the selected option
  }
}



// Populate dropdown option for the Attributes in Custom Query Builder Page

function AttributesCustomPage() {

// Get the checkboxes and the select elements
const objectClassCheckboxes = document.querySelectorAll("#Custom .form-check-input");
const attributeSelects = document.querySelectorAll("#Custom .attribute-column select");

// Define the attribute options for each object class
const attributeOptions = {
  user: ["name", "givenName", "sn","sAMAccountName","description","countryCode","objectSid","memberOf","servicePrincipalName","badPwdCount","logonCount","adminCount","userAccountControl","isCriticalSystemObject"],
  computer: ["name", "sAMAccountName", "dNSHostName","countryCode","objectGUID","objectSid","operatingSystem","badPwdCount","isCriticalSystemObject"],
  group: ["cn", "description", "groupType","member"],
  organizationalUnit: ["cn", "description", "ou"]
};

// Function to update the attribute options based on the selected object classes
function updateAttributeOptions() {
  // Reset the attribute options
  attributeSelects.forEach((select) => {
    select.innerHTML = "<option value=''>Please Select</option>";
  });

  // Get the selected object classes
  const selectedObjectClasses = Array.from(objectClassCheckboxes)
    .filter((checkbox) => checkbox.checked)
    .map((checkbox) => checkbox.id);

  // Add disabled options as group headers
  selectedObjectClasses.forEach((objectClass) => {
    const groupHeader = document.createElement("option");
    groupHeader.value = "";
    groupHeader.textContent = objectClass;
    groupHeader.disabled = true;

    attributeSelects.forEach((select) => {
      select.appendChild(groupHeader.cloneNode(true));
    });

    // Add attributes to the select elements
    attributeOptions[objectClass].forEach((attribute) => {
      attributeSelects.forEach((select) => {
        const option = document.createElement("option");
        option.value = attribute;
        option.textContent = attribute;
        select.appendChild(option);
      });
    });
  });
}

// Add event listener to the checkboxes
objectClassCheckboxes.forEach((checkbox) => {
  checkbox.addEventListener("change", updateAttributeOptions);
});

}






// Call the function with the desired value to populate and center the dropdowns

function populateDropdownOptions(selectElement, options, clearOptions = false) {
  if (clearOptions) {
    // Clear existing options
    selectElement.innerHTML = "";
  }

  // Create new options
  options.forEach(function (option) {
    const optionElement = document.createElement("option");
    optionElement.value = option.value;
    optionElement.textContent = option.text;
    selectElement.appendChild(optionElement);
  });
}


function SwitchColorMode() {
  if (document.documentElement.getAttribute('data-bs-theme') === 'dark') {
    document.documentElement.setAttribute('data-bs-theme', 'light');

    var elements = document.querySelectorAll(".dark");

    for (var i = 0; i < elements.length; i++) {
      elements[i].classList.remove("dark");
      elements[i].classList.add("light");
    }
    document.documentElement.setAttribute('data-theme', 'light');
    localStorage.setItem('theme', 'light'); //add this
    document.getElementById("Switch-Color").innerHTML = " Dark Mode";
  } else {
    document.documentElement.setAttribute('data-bs-theme', 'dark');
    var elements = document.querySelectorAll(".light");

    for (var i = 0; i < elements.length; i++) {
      elements[i].classList.remove("light");
      elements[i].classList.add("dark");
    }
    document.documentElement.setAttribute('data-theme', 'dark');
    localStorage.setItem('theme', 'dark'); //add this
    document.getElementById("Switch-Color").innerHTML = " Light Mode";

  }
}


function disableElements(value) {

  const attribute1Select = document.getElementById("Attribute1");
  const attribute2Select = document.getElementById("Attribute2");
  const attribute3Select = document.getElementById("Attribute3");
  const searchValue1Input = document.getElementById("SearchValue1");
  const searchValue2Input = document.getElementById("SearchValue2");
  const searchValue3Input = document.getElementById("SearchValue3");
  const condition1Select = document.getElementById("Condition1");
  const condition2Select = document.getElementById("Condition2");
  const condition3Select = document.getElementById("Condition3");


  if (value === 1) {
    attribute1Select.disabled = false;
    searchValue1Input.disabled = false;
    condition1Select.disabled = false;
    attribute2Select.disabled = true;
    searchValue2Input.disabled = true;
    condition2Select.disabled = true;
    attribute3Select.disabled = true;
    searchValue3Input.disabled = true;
    condition3Select.disabled = true;
  } 

  else if (value === 2) {
    attribute1Select.disabled = false;
    searchValue1Input.disabled = false;
    condition1Select.disabled = false;
    attribute2Select.disabled = false;
    searchValue2Input.disabled = false;
    condition2Select.disabled = false;
    attribute3Select.disabled = true;
    searchValue3Input.disabled = true;
    condition3Select.disabled = true;
  } 

  else if (value === 3) {
    attribute1Select.disabled = false;
    searchValue1Input.disabled = false;
    condition1Select.disabled = false;
    attribute2Select.disabled = false;
    searchValue2Input.disabled = false;
    condition2Select.disabled = false;
    attribute3Select.disabled = false;
    searchValue3Input.disabled = false;
    condition3Select.disabled = false;
    }

  // Apply styles to disabled elements
  applyDisabledStyles();
}

function applyDisabledStyles() {
  const disabledElements = document.querySelectorAll("select:disabled, input:disabled");
  const enabledElements = document.querySelectorAll("select:not(:disabled), input:not(:disabled)");

  disabledElements.forEach(function (element) {
    element.style.backgroundColor = "#f5f5f5"; // Change to desired grey color
    element.style.color = "#777"; // Change to desired text color
  });

  enabledElements.forEach(function (element) {
    element.style.backgroundColor = ""; // Reset element background color
    element.style.color = ""; // Reset element text color
  });
}

// Call the function to disable elements and apply styles



//Function for the Custom Query Builder Page
//Additional Attributes Count + AND -
function AttributeCount() {
  const plus = document.querySelector(".plus-btn");
  const minus = document.querySelector(".minus-btn");
  const num = document.querySelector(".num");
  let a = 1;
  disableElements(a);

  //triggered when plus icon is clicked
  plus.addEventListener("click", () => {
    if (a < 3) {
      a++;
      num.value = a;
      disableElements(a);
      ConditionOptions(a);
      


    }
  });

  //triggered when minus icon is clicked
  minus.addEventListener("click", () => {
    if (a > 1) {
      a--;
      num.value = a;
      disableElements(a);
      ConditionOptions(a);
    }
  });
}



// DOM 
document.addEventListener("DOMContentLoaded", function () {

  // set a default LDAP IP address and set nmap command 
  //document.getElementById("LDAP_IP").value = "10.10.10.10";
  var input = document.getElementById("LDAP_IP");
  input.addEventListener("input", SetLDAP);


  // set a default LDAP Port and set nmap command 
  document.getElementById("LDAP_PORT").value = "389";
  var input = document.getElementById("LDAP_PORT");
  input.addEventListener("input", SetLDAP);

  // Default Opening the first tab
  document.getElementById("PreBuiltOpen").click();

  // to add onmouseleave and onclick into all copy button
  var cpbtns = document.querySelectorAll("button[id^='Copy']");
  for (var i = 0; i < cpbtns.length; i++) {
    cpbtns[i].addEventListener("mouseleave", ResetToClip);
    cpbtns[i].addEventListener("click", CopyToClip);
  }

  //onload function
  BuiltInQueries();
  AttributeCount();
  document.querySelectorAll(".form-check-input").forEach(function (checkbox) {
  checkbox.addEventListener("change", function() {
    if (this.checked) {
      ConditionOptions(3);
    }
  });
});
  AttributesCustomPage();
  NSEDefinition();
  SwitchColorMode();
  document.getElementById('Switch-Color').addEventListener('click', SwitchColorMode);

});


