void FUN_140007f90(longlong *param_1,undefined8 param_2,undefined8 param_3)

{
  code *pcVar1;
  longlong *plVar2;
  short *psVar3;
  LPCWSTR ***ppppWVar4;
  longlong lVar5;
  longlong lVar6;
  ulonglong uVar7;
  undefined1 auStack_b8 [32];
  longlong *local_98;
  longlong local_90;
  longlong local_88;
  LPCWSTR **local_80 [3];
  ulonglong local_68;
  longlong local_60;
  longlong local_58;
  longlong local_50 [4];
  char local_30;
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStack_b8;
  lVar5 = 0;
  local_60 = 0;
  local_58 = 0;
  local_98 = param_1;
  FUN_140007d80(local_50,param_2,param_3);
  if (local_30 == '\0') {
    *param_1 = 0;
    param_1[2] = 0;
    param_1[3] = 7;
    *(undefined2 *)param_1 = 0;
    FUN_14000d470(local_50);
  }
  else {
    local_98 = (longlong *)((ulonglong)local_98 & 0xffffffff00000000);
    FUN_14000e750(local_80,local_50);
    ppppWVar4 = local_80;
    if (7 < local_68) {
      ppppWVar4 = (LPCWSTR ***)local_80[0];
    }
    plVar2 = (longlong *)FUN_140012520(&local_90,(LPCWSTR)ppppWVar4,param_3,(DWORD *)&local_98);
    lVar6 = lVar5;
    if (&local_60 != plVar2) {
      lVar5 = plVar2[1];
      plVar2[1] = 0;
      lVar6 = *plVar2;
      *plVar2 = 0;
      local_60 = lVar6;
      local_58 = lVar5;
    }
    if (local_88 != 0) {
      (*(code *)PTR__guard_dispatch_icall_14005b538)();
    }
    if (local_90 != 0) {
      (*(code *)PTR__guard_dispatch_icall_14005b538)(local_90,1);
    }
    if (7 < local_68) {
      if ((0xfff < local_68 * 2 + 2) &&
         (0x1f < (ulonglong)((longlong)local_80[0] + (-8 - (longlong)local_80[0][-1])))) {
        FUN_140035d28();
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
      FUN_14002f180();
    }
    if ((lVar5 == 0) || ((int)local_98 != 0)) {
      *param_1 = 0;
      param_1[2] = 0;
      param_1[3] = 7;
      *(undefined2 *)param_1 = 0;
      FUN_14000d470(local_50);
      if (lVar5 != 0) {
        (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar6);
      }
      if (lVar6 != 0) {
        (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar6,1);
      }
    }
    else {
      FUN_14000d470(local_50);
      psVar3 = (short *)(*(code *)PTR__guard_dispatch_icall_14005b538)(lVar5,2,L"common");
      if ((psVar3 == (short *)0x0) || (*psVar3 == 0x3c)) {
        *param_1 = 0;
        param_1[2] = 0;
        param_1[3] = 7;
        *(undefined2 *)param_1 = 0;
        (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar6);
        (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar6,1);
      }
      else {
        *param_1 = 0;
        param_1[2] = 0;
        param_1[3] = 7;
        *(undefined2 *)param_1 = 0;
        uVar7 = 0xffffffffffffffff;
        do {
          uVar7 = uVar7 + 1;
        } while (psVar3[uVar7] != 0);
        FUN_140010340(param_1,(undefined8 *)psVar3,uVar7);
        (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar6);
        (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar6,1);
      }
    }
  }
  FUN_14002f160(local_28 ^ (ulonglong)auStack_b8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140008220 @ 140008220