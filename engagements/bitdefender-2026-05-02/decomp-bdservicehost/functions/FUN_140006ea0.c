void FUN_140006ea0(longlong param_1)

{
  undefined8 uVar1;
  longlong *plVar2;
  undefined8 local_18;
  undefined8 local_10;
  
  (*(code *)PTR__guard_dispatch_icall_14005b538)();
  (*(code *)PTR__guard_dispatch_icall_14005b538)();
  local_18 = 0xbc90fca366551ab3;
  local_10 = 0x514be292f7c5425f;
  uVar1 = (*(code *)PTR__guard_dispatch_icall_14005b538)(*(undefined8 *)(param_1 + 0x40),&local_18);
  plVar2 = (longlong *)(param_1 + 0x20);
  if (7 < *(ulonglong *)(param_1 + 0x38)) {
    plVar2 = (longlong *)*plVar2;
  }
  (*(code *)PTR__guard_dispatch_icall_14005b538)(plVar2,uVar1);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140006f20 @ 140006f20