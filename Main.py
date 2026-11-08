# Wevorn Offsets Dumper v1.2

from pathlib import Path
import re

# Example (You can add more sections and functions)
Targets = {
   "UserService": {
      "getUserFromGlobalUserIdAsync": {
          "String": "UserService::getUserFromGlobalUserIdAsync", # String to search for in Ghidra
          "String_Contains": False, # Match strings containing the target text (False = exact match)
          "String_Regex": False, # Use regular expressions for string matching
          "XREF_Type": "FUN_", # Filter XREF functions by name prefix
          "Use_XREF": True, # Find functions referencing the target string
          "XREF": 1, # Selects the XREF function by index (1 = first, 2 = second, 0 = all)
          "XREF_Count": 1, # Required exact number of unique referenced functions
          "XREF_Min": 1, # Minimum number of unique functions referencing the string (0 = disabled)
          "XREF_Max": 1, # Maximum number of unique functions referencing the string (0 = disabled)
          "XREF_Min_On_XREF": 2, # Minimum number of references to the selected XREF function (0 = disabled)
          "XREF_Max_On_XREF": 10, # Maximum number of references to the selected XREF function (0 = disabled)
          "XREF_Count_On_XREF": 4, # Required exact number of XREFs referencing the selected XREF function address (0 = disabled)
          "XREF_Unique": False, # Remove duplicate XREF functions
          "XREF_Include_Thunk": False, # Include Thunk functions in XREF results
          "Print_Not_Found": True, # Print functions that were not found
          "Save_Not_Found": True, # Save functions that were not found
      },
   },
}

Use_Print = True # True / False

Output = [
   "// Version: v745",
   "#pragma once",
   "#include <cstdint>\n",
   "namespace Roblox {"
]

Listing = currentProgram.getListing()
ReferenceManager = currentProgram.getReferenceManager()
FunctionManager = currentProgram.getFunctionManager()

def ToRVA(Address):
   return "0x{:X}".format(Address.getOffset() - currentProgram.getImageBase().getOffset())

Results = {Namespace: {} for Namespace in Targets}

for Data in Listing.getDefinedData(True):
   if not Data.hasStringValue():
      continue
   Value = str(Data.getValue())
   for Namespace, Functions in Targets.items():
      for Name, Target in Functions.items():
         if Target.get("String_Regex", False):
            if not re.search(Target["String"], Value):
               continue
         elif Target.get("String_Contains", False):
            if Target["String"] not in Value:
               continue
         elif Value != Target["String"]:
            continue
         if not Target.get("Use_XREF", False):
            Results[Namespace].setdefault(Name, []).append((ToRVA(Data.getAddress()), Data.getAddress()))
            continue
         Found = {}
         FoundList = []
         for Ref in ReferenceManager.getReferencesTo(Data.getAddress()):
            Function = FunctionManager.getFunctionContaining(Ref.getFromAddress())
            if not Function:
               continue
            if not Target.get("XREF_Include_Thunk", False) and Function.isThunk():
               continue
            if Target.get("XREF_Type", "") and not Function.getName().startswith(Target["XREF_Type"]):
               continue
            if Target.get("XREF_Unique", True):
               Found[Function.getEntryPoint()] = Function
            else:
               FoundList.append(Function)
         Found = list(Found.values()) if Target.get("XREF_Unique", True) else FoundList
         XREF_Count = len(Found)
         if Target.get("XREF_Count", 0) != 0 and XREF_Count != Target["XREF_Count"]:
            continue
         if Target.get("XREF_Min", 0) != 0 and XREF_Count < Target["XREF_Min"]:
            continue
         if Target.get("XREF_Max", 0) != 0 and XREF_Count > Target["XREF_Max"]:
            continue
         Limit = Target.get("XREF", 0)
         if Limit != 0:
            Found = Found[Limit - 1:Limit]
         if Target.get("XREF_Count_On_XREF", 0) != 0 or Target.get("XREF_Min_On_XREF", 0) != 0 or Target.get("XREF_Max_On_XREF", 0) != 0:
            Valid = []
            for Function in Found:
               XrefCount = len(list(ReferenceManager.getReferencesTo(Function.getEntryPoint())))
               if Target.get("XREF_Count_On_XREF", 0) != 0 and XrefCount != Target["XREF_Count_On_XREF"]:
                  continue
               if Target.get("XREF_Min_On_XREF", 0) != 0 and XrefCount < Target["XREF_Min_On_XREF"]:
                  continue
               if Target.get("XREF_Max_On_XREF", 0) != 0 and XrefCount > Target["XREF_Max_On_XREF"]:
                  continue
               Valid.append(Function)
            Found = Valid
         Results[Namespace].setdefault(Name, []).extend((ToRVA(Function.getEntryPoint()), Function.getEntryPoint()) for Function in Found)
         if Use_Print:
            for Function in Found:
               print(f"\nNamespace: {Namespace}\nName: {Name}\nString Address: {ToRVA(Data.getAddress())}\nFunction: {Function.getName()}\nFunction Address: {ToRVA(Function.getEntryPoint())}\nXREF Count: {XREF_Count}\nXREF on Function: {len(list(ReferenceManager.getReferencesTo(Function.getEntryPoint())))}")

for Namespace in Results:
   for Name in Results[Namespace]:
      if Targets[Namespace][Name].get("XREF_Unique", True):
         Results[Namespace][Name] = list({Address: (RVA, Address) for RVA, Address in Results[Namespace][Name]}.values())

for Namespace, Functions in Targets.items():
   Output.append("   namespace {} {{".format(Namespace))
   for Name in Functions:
      Found = Results[Namespace].get(Name, [])
      if not Found:
         if Targets[Namespace][Name].get("Print_Not_Found", False):
            print(f"\nNamespace: {Namespace}\nName: {Name}\nStatus: Not found")
         if Targets[Namespace][Name].get("Save_Not_Found", True):
            Output.append("      // {} - Not found".format(Name))
         continue
      for Index, (RVA, Address) in enumerate(Found):
         Symbol = Name if len(Found) == 1 else "{}_{}".format(Name, Index + 1)
         Output.append("      constexpr std::uintptr_t {} = {}; // Ghidra: 0x{:X}".format(Symbol, RVA, Address.getOffset()))
   Output.append("   }")
Output.append("}")

OutputPath = Path.cwd() / "offsets.h"
OutputPath.write_text("\n".join(Output) + "\n", encoding="utf-8")
