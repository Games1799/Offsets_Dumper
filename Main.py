# Wevorn Offsets Dumper v1.1

from pathlib import Path

# Example (You can add more sections and functions)
Targets = {
   "UserService": {
      "getUserFromGlobalUserIdAsync": {
          "String": "UserService::getUserFromGlobalUserIdAsync", # String to search for in Ghidra
          "XREF_Type": "FUN_", # Filter XREF functions by name prefix
          "Use_XREF": True, # Find functions referencing the target string
          "XREF": 1, # Selects the XREF function by index (1 = first, 2 = second, 0 = all)
          "XREF_Count": 1, # Required exact number of unique referenced functions
          "Xref_Count_On_XREF": 4, # Required exact number of XREFs referencing the selected XREF function address (0 = disabled)
      },
   },
}

Use_Print = False # True/False

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
         if Value != Target["String"]:
            continue
         if not Target.get("Use_XREF", False):
            Results[Namespace][Name] = [(ToRVA(Data.getAddress()), Data.getAddress())]
            continue
         Found = {}
         for Ref in ReferenceManager.getReferencesTo(Data.getAddress()):
            Function = FunctionManager.getFunctionContaining(Ref.getFromAddress())
            if not Function:
               continue
            if Target.get("XREF_Type", "") and not Function.getName().startswith(Target["XREF_Type"]):
               continue
            Found[Function.getEntryPoint()] = Function
         Found = list(Found.values())
         XREF_Count = len(Found)
         if Target.get("XREF_Count", 0) != 0 and XREF_Count != Target["XREF_Count"]:
            continue
         Limit = Target.get("XREF", 0)
         if Limit != 0:
            Found = Found[Limit - 1:Limit]
         if Target.get("Xref_Count_On_XREF", 0) != 0:
            Valid = []
            for Function in Found:
               XrefCount = len(list(ReferenceManager.getReferencesTo(Function.getEntryPoint())))
               if XrefCount == Target["Xref_Count_On_XREF"]:
                  Valid.append(Function)
            Found = Valid
         Results[Namespace][Name] = [(ToRVA(Function.getEntryPoint()), Function.getEntryPoint()) for Function in Found]
         if Use_Print:
            for Function in Found:
               print(Namespace, Name, ToRVA(Data.getAddress()), Function.getName(), ToRVA(Function.getEntryPoint()), "XREF:", XREF_Count)

for Namespace, Functions in Targets.items():
   Output.append("   namespace {} {{".format(Namespace))
   for Name in Functions:
      Found = Results[Namespace].get(Name, [])
      if not Found:
         Output.append("      // {} - Not found".format(Name))
         continue
      for Index, (RVA, Address) in enumerate(Found):
         Symbol = Name if len(Found) == 1 else "{}_{}".format(Name, Index + 1)
         Output.append("      constexpr std::uintptr_t {} = {}; // Ghidra: 0x{:X}".format(Symbol, RVA, Address.getOffset()))
   Output.append("   }")
Output.append("}")

OutputPath = Path.cwd() / "offsets.h"
OutputPath.write_text("\n".join(Output) + "\n", encoding="utf-8")
