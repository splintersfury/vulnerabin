void FUN_140001c20(undefined8 *param_1,undefined8 *param_2,undefined8 *param_3)

{
  code *pcVar1;
  undefined8 uVar2;
  longlong *plVar3;
  undefined8 ****ppppuVar4;
  undefined1 auStack_b8 [32];
  longlong *local_98;
  undefined8 ***local_90;
  longlong lStack_88;
  longlong local_80;
  ulonglong uStack_78;
  undefined8 local_70 [5];
  undefined8 ***local_48;
  undefined4 uStack_40;
  undefined4 uStack_3c;
  ulonglong local_38;
  ulonglong local_30;
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStack_b8;
  local_98 = param_1;
  plVar3 = FUN_14000e990(local_70,param_3);
  local_48 = (undefined8 ***)*param_2;
  uStack_40 = *(undefined4 *)(param_2 + 1);
  uStack_3c = *(undefined4 *)((longlong)param_2 + 0xc);
  local_98 = plVar3;
  if (plVar3[2] != 0) {
    FUN_140010800(plVar3,(undefined8 *)&DAT_14006a930,2);
  }
  (*(code *)PTR__guard_dispatch_icall_14005b538)
            (CONCAT44(uStack_3c,uStack_40),&local_48,(ulonglong)local_48 & 0xffffffff);
  ppppuVar4 = &local_48;
  if (0xf < local_30) {
    ppppuVar4 = (undefined8 ****)local_48;
  }
  FUN_140010800(plVar3,ppppuVar4,local_38);
  if (0xf < local_30) {
    if ((0xfff < local_30 + 1) &&
       (0x1f < (ulonglong)((longlong)local_48 + (-8 - (longlong)local_48[-1])))) goto LAB_140001dc1;
    FUN_14002f180();
  }
  local_90 = (undefined8 ***)*plVar3;
  lStack_88 = plVar3[1];
  local_80 = plVar3[2];
  uStack_78 = plVar3[3];
  plVar3[2] = 0;
  plVar3[3] = 0xf;
  *(undefined1 *)plVar3 = 0;
  local_48 = &local_90;
  if (0xf < uStack_78) {
    local_48 = local_90;
  }
  *param_1 = std::exception::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  uStack_40 = CONCAT31(uStack_40._1_3_,1);
  __std_exception_copy((longlong *)&local_48,param_1 + 1);
  *param_1 = std::runtime_error::vftable;
  if (0xf < uStack_78) {
    if ((0xfff < uStack_78 + 1) &&
       (0x1f < (ulonglong)((longlong)local_90 + (-8 - (longlong)local_90[-1])))) {
      FUN_140035d28();
LAB_140001dc1:
      FUN_140035d28();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    FUN_14002f180();
  }
  *param_1 = std::_System_error::vftable;
  uVar2 = param_2[1];
  param_1[3] = *param_2;
  param_1[4] = uVar2;
  FUN_14002f160(local_28 ^ (ulonglong)auStack_b8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140001dd0 @ 140001dd0