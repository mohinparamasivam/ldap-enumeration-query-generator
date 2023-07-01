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

  alert(PreBuiltMode.value);
  //Set the ADSearch , LDAPSearch and Raw LDAP Query Value


  // IF Statement if domain has 3 parts

  if (domain_array.length===3){

    //Find All Domain Users
  if (PreBuiltMode.value === "(&(objectCategory=user)(objectClass=user))") {
    var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+PreBuiltMode.value+"\"";
    var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+PreBuiltMode.value+"\"";
    var RAW_Command = PreBuiltMode.value;

    document.getElementById("ADSearch_Command").value = ADSearch_Command;
    document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
    document.getElementById("RAW_Command").value = RAW_Command;


  }

  else if (PreBuiltMode.value === "mohin") {
    var ADSearch_Command = "nmap hello"; 
    document.getElementById("NSE-Nmap1").value = ADSearch_Command;
  }

  }

  // IF Statement if domain has 2 parts

  else if (domain_array.length===2){
    //Find All Domain Users
  if (PreBuiltMode.value === "(&(objectCategory=user)(objectClass=user))") {
    var ADSearch_Command = "ADSearch.exe --domain " +domain+" --search \""+PreBuiltMode.value+"\"";
    var LDAPSearch_Command  = "ldapsearch -x -h " +ip+" -p "+port+" -b \""+"DC="+domain_part1+",DC="+domain_part2+",DC="+domain_part3+"\" "+"\""+PreBuiltMode.value+"\"";
    var RAW_Command = PreBuiltMode.value;

    document.getElementById("ADSearch_Command").value = ADSearch_Command;
    document.getElementById("LDAPSearch_Command").value = LDAPSearch_Command;
    document.getElementById("RAW_Command").value = RAW_Command;


  }

  else if (PreBuiltMode.value === "mohin") {
    var ADSearch_Command = "nmap hello"; 
    document.getElementById("NSE-Nmap1").value = ADSearch_Command;
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
function CategoryNSE() {

  var domain_part1 = document.getElementById("Domain");
  var options = [
    { value: "", text: "Please Select" },
    { value: "mohin", text: "mohin" },
    { value: "(&(objectCategory=user)(objectClass=user))", text: "Find all Domain Users" },
    { value: "(&(objectCategory=user)(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,DC="+domain_part1+",DC="+domain_part1+"))", text: "Find all Domain Admins" },
    { value: "Domain-Admins", text: "Find all Domain Groups" },
    { value: "Domain-Admins", text: "Find Domain Groups ending with 'admin' keyword" },
    { value: "Domain-Users", text: "Find Domain Users with password never expires enabled" },
    { value: "Domain-Admins", text: "Find Domain Controllers" },
    { value: "Domain-Admins", text: "Find Domain Computers" },
    { value: "Domain-Admins", text: "Find Decoy HoneyPot Accounts" },
    { value: "Domain-Admins", text: "Find Default User Accounts with password in Description" },
    { value: "Domain-Admins", text: "Map Domain Trusts" },
    { value: "Domain-Admins", text: "Find Principals with DCSync Rights" },
    { value: "Domain-Admins", text: "List all Kerberoastable Accounts" },
    { value: "Domain-Admins", text: "Find AS-REP Roastable Users (DontReqPreAuth)" },
    { value: "Domain-Admins", text: "Find UnConstrained Delegration Enabled Workstations" },
    { value: "Domain-Admins", text: "Find Constrained Delegration Enabled Workstations" },
    { value: "Domain-Admins", text: "Find Workstations where Domain Users can RDP" },
    { value: "Domain-Admins", text: "Find LAPS Enabled Workstations" }
  ];



  var PreBuiltQuery = document.getElementById("PreBuilt-Mode");

  options.forEach(function (option) {
    var optionElement = document.createElement("option");
    optionElement.value = option.value;
    optionElement.text = option.text;
    PreBuiltQuery.appendChild(optionElement);
  });

  PreBuiltQuery.value = "Please Select";

  PreBuiltQuery.addEventListener("change", SetLDAP);

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




// DOM 
document.addEventListener("DOMContentLoaded", function () {

  // set a default LDAP IP address and set nmap command 
  document.getElementById("LDAP_IP").value = "10.10.10.10";
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
  CategoryNSE();
  NSEDefinition();
  SwitchColorMode();

  
  document.getElementById('Switch-Color').addEventListener('click', SwitchColorMode);

});


