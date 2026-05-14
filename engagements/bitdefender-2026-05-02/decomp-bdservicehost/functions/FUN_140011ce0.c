void FUN_140011ce0(longlong param_1,undefined8 param_2)

{
  undefined2 uVar1;
  undefined8 *puVar2;
  _Locimp *p_Var3;
  undefined8 uVar4;
  longlong lVar5;
  undefined1 local_18 [8];
  longlong local_10;
  
  *(undefined8 *)(param_1 + 0x40) = 0;
  *(undefined8 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined4 *)(param_1 + 0x18) = 0x201;
  *(undefined8 *)(param_1 + 0x20) = 6;
  *(undefined8 *)(param_1 + 0x28) = 0;
  *(undefined8 *)(param_1 + 0x30) = 0;
  *(undefined8 *)(param_1 + 0x38) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  puVar2 = (undefined8 *)operator_new(0x10);
  *puVar2 = 0;
  puVar2[1] = 0;
  p_Var3 = std::locale::_Init(true);
  puVar2[1] = p_Var3;
  *(undefined8 **)(param_1 + 0x40) = puVar2;
  *(undefined8 *)(param_1 + 0x48) = param_2;
  *(undefined8 *)(param_1 + 0x50) = 0;
  local_10 = puVar2[1];
  (*(code *)PTR__guard_dispatch_icall_14005b538)();
  uVar4 = FUN_140013c80((longlong)local_18);
  uVar1 = (*(code *)PTR__guard_dispatch_icall_14005b538)(uVar4,0x20);
  if (local_10 != 0) {
    lVar5 = (*(code *)PTR__guard_dispatch_icall_14005b538)();
    if (lVar5 != 0) {
      (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar5,1);
    }
  }
  *(undefined2 *)(param_1 + 0x58) = uVar1;
  if (*(longlong *)(param_1 + 0x48) == 0) {
    FUN_140002cd0(param_1,*(uint *)(param_1 + 0x10) | 4,'\0');
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140011df0 @ 140011df0