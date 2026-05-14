longlong FUN_14001bec0(longlong *param_1,undefined8 *param_2,ulonglong param_3)

{
  longlong lVar1;
  int iVar2;
  ulonglong uVar3;
  size_t sVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  
  uVar5 = param_3;
  if (param_1[0xd] == 0) {
    if (*(undefined8 **)param_1[8] == (undefined8 *)0x0) {
      iVar2 = 0;
    }
    else {
      iVar2 = *(int *)param_1[0xb];
    }
    if (0 < (longlong)param_3) {
      if (0 < iVar2) {
        uVar3 = (longlong)iVar2;
        if ((longlong)param_3 < (longlong)iVar2) {
          uVar3 = param_3;
        }
        FUN_1400316b0(*(undefined8 **)param_1[8],param_2,uVar3);
        uVar5 = param_3 - uVar3;
        param_2 = (undefined8 *)((longlong)param_2 + uVar3);
        *(int *)param_1[0xb] = *(int *)param_1[0xb] - (int)uVar3;
        *(longlong *)param_1[8] = *(longlong *)param_1[8] + (longlong)(int)uVar3;
        if ((longlong)uVar5 < 1) goto LAB_14001bfd5;
      }
      if ((FILE *)param_1[0x10] != (FILE *)0x0) {
        sVar4 = fwrite(param_2,1,uVar5,(FILE *)param_1[0x10]);
        uVar5 = uVar5 - sVar4;
      }
    }
  }
  else if (0 < (longlong)param_3) {
    do {
      uVar3 = FUN_140010160((longlong)param_1);
      if ((longlong)uVar3 < 1) {
        iVar2 = (*(code *)PTR__guard_dispatch_icall_14005b538)(param_1,*(undefined1 *)param_2);
        if (iVar2 == -1) break;
        lVar1 = -1;
        uVar6 = 1;
      }
      else {
        uVar6 = uVar5;
        if ((longlong)uVar3 <= (longlong)uVar5) {
          uVar6 = uVar3;
        }
        FUN_1400316b0(*(undefined8 **)param_1[8],param_2,uVar6);
        lVar1 = -uVar6;
        *(int *)param_1[0xb] = *(int *)param_1[0xb] - (int)uVar6;
        *(longlong *)param_1[8] = *(longlong *)param_1[8] + (longlong)(int)uVar6;
      }
      uVar5 = uVar5 + lVar1;
      param_2 = (undefined8 *)((longlong)param_2 + uVar6);
    } while (0 < (longlong)uVar5);
  }
LAB_14001bfd5:
  return param_3 - uVar5;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001bff0 @ 14001bff0