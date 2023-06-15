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

  // Host Discovery
  var NmapsL = document.getElementById("Nmap-sL");
  var Nmapsn = document.getElementById("Nmap-sn");
  var NmapPn = document.getElementById("Nmap-Pn");
  var Nmaptraceroute = document.getElementById("Nmap-traceroute");

  // Scan Technique
  var NmapsS = document.getElementById("Nmap-sS");
  var NmapsT = document.getElementById("Nmap-sT");
  var NmapsW = document.getElementById("Nmap-sW");
  var NmapsN = document.getElementById("Nmap-sN");
  var NmapsF = document.getElementById("Nmap-sF");
  var NmapsX = document.getElementById("Nmap-sX");
  var NmapsO = document.getElementById("Nmap-sO");
  var NmapsU = document.getElementById("Nmap-sU");

  // Misc
  var NmapsV = document.getElementById("Nmap-sV");
  var NmapsC = document.getElementById("Nmap-sC");
  var NmapO = document.getElementById("Nmap-O");
  var NmapA = document.getElementById("Nmap-A");
  var Nmap6 = document.getElementById("Nmap-6");
  var Nmapv = document.getElementById("Nmap-v");

  // Port Specification
  var NmapFullPort = document.getElementById("Nmap-Full-Port");
  var Nmap1000Port = document.getElementById("Nmap-1000-Port");
  var NmapCustomPort = document.getElementById("Nmap-Custom-Port");
  var PortNumber = document.getElementById("Port-Number");
  var NmapExcludePort = document.getElementById("Nmap-Exclude-Port");
  var ExcludePortNumber = document.getElementById("Exclude-Port-Number");
  var NmapScanSequence = document.getElementById("Nmap-Scan-Sequence");

  //Timing and Performance
  var NmapT0 = document.getElementById("Nmap-T0");
  var NmapT1 = document.getElementById("Nmap-T1");
  var NmapT2 = document.getElementById("Nmap-T2");
  var NmapT3 = document.getElementById("Nmap-T3");
  var NmapT4 = document.getElementById("Nmap-T4");
  var NmapT5 = document.getElementById("Nmap-T5");

  // File Output
  var NmapDOutput = document.getElementById("Nmap-DOutput");
  var NmapoN = document.getElementById("Nmap-oN");
  var NmapoX = document.getElementById("Nmap-oX");
  var NmapoS = document.getElementById("Nmap-oS");
  var NmapoG = document.getElementById("Nmap-oG");
  var NmapoA = document.getElementById("Nmap-oA");
  var OutputName = document.getElementById("Output-Name");

  //NSE
  var NSECategory = document.getElementById("NSE-Category");
  var NSESpecific = document.getElementById("NSE-Specific");
  var NSEPort = document.getElementById("NSE-Port");
  var NSEPortNumber = document.getElementById("NSE-Port-Number");

  // Set Nmap Option
  // Host Discovery
  NmapsL.value = "-sL";
  Nmapsn.value = "-sn";
  NmapPn.value = "-Pn";
  Nmaptraceroute.value = "--traceroute";

  // Scan Technique
  NmapsS.value = "-sS";
  NmapsT.value = "-sT";
  NmapsW.value = "-sW";
  NmapsN.value = "-sN";
  NmapsF.value = "-sF";
  NmapsX.value = "-sX";
  NmapsO.value = "-sO";
  NmapsU.value = "-sU";

  // Misc
  NmapsV.value = "-sV";
  NmapsC.value = "-sC";
  NmapO.value = "-O";
  NmapA.value = "-A";
  Nmap6.value = "-6";
  Nmapv.value = "-v";

  // Port Specification
  NmapFullPort.value = "-p-";
  Nmap1000Port.value = "";
  NmapCustomPort.value = "-p";
  NmapExcludePort.value = "--exclude-ports";
  NmapScanSequence.value = "-r";

  // Timing and Performance
  NmapT0.value = "";
  NmapT1.value = "-T1";
  NmapT2.value = "-T2";
  NmapT3.value = "-T3";
  NmapT4.value = "-T4";
  NmapT5.value = "-T5";

  // File Output
  NmapDOutput.value = "";
  NmapoN.value = "-oN";
  NmapoX.value = "-oX";
  NmapoS.value = "-oS";
  NmapoG.value = "-oG";
  NmapoA.value = "-oA";


  // Simple Mode
  document.getElementById("Basic-Scan").value = `nmap ${ip}`;
  document.getElementById("Full-Port-Scan").value = `nmap ${ip} -p-`;
  document.getElementById("Default-Script-Scan").value = `nmap ${ip} -sC`;
  document.getElementById("Full-Scan").value = `nmap ${ip} -p- -A`;
  document.getElementById("Scan-Save-Output").value = `nmap ${ip} -oN output.nmap`;

  // Advance Mode
  var AdvanceNmap = "nmap " + ip;

  if (NmapsL.checked) {
    AdvanceNmap += " " + NmapsL.value;
  }

  if (Nmapsn.checked) {
    AdvanceNmap += " " + Nmapsn.value;
  }

  if (NmapPn.checked) {
    AdvanceNmap += " " + NmapPn.value;
  }

  if (Nmaptraceroute.checked) {
    AdvanceNmap += " " + Nmaptraceroute.value;
  }

  if (NmapsS.checked) {
    AdvanceNmap += " " + NmapsS.value;
  }

  if (NmapsT.checked) {
    AdvanceNmap += " " + NmapsT.value;
  }

  if (NmapsW.checked) {
    AdvanceNmap += " " + NmapsW.value;
  }

  if (NmapsN.checked) {
    AdvanceNmap += " " + NmapsN.value;
  }

  if (NmapsF.checked) {
    AdvanceNmap += " " + NmapsF.value;
  }

  if (NmapsX.checked) {
    AdvanceNmap += " " + NmapsX.value;
  }

  if (NmapsO.checked) {
    AdvanceNmap += " " + NmapsO.value;
  }

  if (NmapsU.checked) {
    AdvanceNmap += " " + NmapsU.value;
  }

  if (NmapsV.checked) {
    AdvanceNmap += " " + NmapsV.value;
  }

  if (NmapsC.checked) {
    AdvanceNmap += " " + NmapsC.value;
  }

  if (NmapO.checked) {
    AdvanceNmap += " " + NmapO.value;
  }

  if (NmapA.checked) {
    AdvanceNmap += " " + NmapA.value;
  }

  if (Nmap6.checked) {
    AdvanceNmap += " " + Nmap6.value;
  }

  if (Nmapv.checked) {
    AdvanceNmap += " " + Nmapv.value;
  }

  if (NmapFullPort.checked) {
    AdvanceNmap += " " + NmapFullPort.value;
  }

  if (PortNumber.disabled == false && PortNumber.value !== "") {

    if (NmapCustomPort.checked) {
      AdvanceNmap += " " + NmapCustomPort.value;
    }

    AdvanceNmap += " " + PortNumber.value;
  }

  if (ExcludePortNumber.disabled == false && ExcludePortNumber.value !== "") {

    if (NmapExcludePort.checked) {

      AdvanceNmap += " " + NmapExcludePort.value;

    }
    AdvanceNmap += " " + ExcludePortNumber.value;

  }

  if (NmapScanSequence.checked) {

    AdvanceNmap += " " + NmapScanSequence.value;
  }

  if (NmapT1.checked) {
    AdvanceNmap += " " + NmapT1.value;
  }

  if (NmapT2.checked) {
    AdvanceNmap += " " + NmapT2.value;
  }

  if (NmapT3.checked) {
    AdvanceNmap += " " + NmapT3.value;
  }

  if (NmapT4.checked) {
    AdvanceNmap += " " + NmapT4.value;
  }

  if (NmapT5.checked) {
    AdvanceNmap += " " + NmapT5.value;
  }

  if (OutputName.disabled == false && OutputName.value !== "") {

    if (NmapoN.checked) {
      AdvanceNmap += " " + NmapoN.value;
    }

    if (NmapoX.checked) {
      AdvanceNmap += " " + NmapoX.value;
    }

    if (NmapoS.checked) {
      AdvanceNmap += " " + NmapoS.value;
    }

    if (NmapoG.checked) {
      AdvanceNmap += " " + NmapoG.value;
    }

    if (NmapoA.checked) {
      AdvanceNmap += " " + NmapoA.value;
    }
    AdvanceNmap += " " + OutputName.value;
  }

  document.getElementById("Advance-Nmap").value = AdvanceNmap;



  //NSE Mode
  var NSENmap = "nmap " + ip;

  if (NSEPort.checked == true && NSEPortNumber.value !== "") {
    NSENmap += " -p " + NSEPortNumber.value
  }

  if (NSECategory.value === "default") {
    NSENmap += " -sC"
  } else if (NSECategory.value !== "specific") {
    NSENmap += " --script=" + NSECategory.value;
  }

  if (NSESpecific.value !== "" && NSECategory.value === "specific") {
    NSENmap += " --script=" + NSESpecific.value;
  }
  document.getElementById("NSE-Nmap").value = NSENmap;
}

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
  var options = [
    { value: "", text: "Please Select" },
    { value: "Domain-Users", text: "Find all Domain Users" },
    { value: "Domain-Admins", text: "Find all Domain Admins" },
    { value: "Domain-Admins", text: "Find all Domain Groups" },
    { value: "Domain-Admins", text: "Find Domain Groups ending with 'admin' keyword" },
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
  DisableEnableInput();
  SetLDAP();
  NSEDefinition();
  SwitchColorMode();

  
  document.getElementById('Switch-Color').addEventListener('click', SwitchColorMode);

});


