void FUN_14001f280(longlong param_1,longlong *param_2,ulonglong param_3)

{
  byte bVar1;
  byte *pbVar2;
  ulonglong uVar3;
  longlong lVar4;
  longlong *plVar5;
  byte *pbVar6;
  ulonglong uVar7;
  undefined1 auStack_58 [32];
  undefined4 local_38;
  longlong *local_30;
  undefined8 local_28;
  undefined1 local_20;
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStack_58;
  *param_2 = 0;
  param_2[2] = 0;
  param_2[3] = 0xf;
  *(undefined1 *)param_2 = 0;
  local_38 = 1;
  pbVar2 = *(byte **)(param_1 + 0x38);
  local_30 = param_2;
  for (pbVar6 = *(byte **)(param_1 + 0x30); pbVar6 != pbVar2; pbVar6 = pbVar6 + 1) {
    bVar1 = *pbVar6;
    if (bVar1 < 0x20) {
      local_28 = 0;
      local_20 = 0;
      FUN_14002a5e0((char *)&local_28,9,"<U+%.4X>",(ulonglong)bVar1);
      uVar7 = 0xffffffffffffffff;
      do {
        param_3 = uVar7 + 1;
        lVar4 = uVar7 + 1;
        uVar7 = param_3;
      } while (*(char *)((longlong)&local_28 + lVar4) != '\0');
      FUN_140010800(param_2,&local_28,param_3);
    }
    else {
      uVar7 = param_2[2];
      uVar3 = param_2[3];
      if (uVar7 < uVar3) {
        param_2[2] = uVar7 + 1;
        plVar5 = param_2;
        if (0xf < uVar3) {
          plVar5 = (longlong *)*param_2;
        }
        *(byte *)((longlong)plVar5 + uVar7) = bVar1;
        *(undefined1 *)((longlong)plVar5 + uVar7 + 1) = 0;
      }
      else {
        FUN_1400137e0(param_2,uVar3,param_3,bVar1);
      }
    }
  }
  FUN_14002f160(local_18 ^ (ulonglong)auStack_58);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001f390 @ 14001f390