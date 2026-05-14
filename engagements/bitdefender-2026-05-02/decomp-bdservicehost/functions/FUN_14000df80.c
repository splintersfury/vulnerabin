longlong FUN_14000df80(longlong *param_1,undefined8 *param_2,longlong param_3)

{
  short sVar1;
  longlong lVar2;
  longlong lVar3;
  ulonglong uVar4;
  longlong lVar5;
  
  lVar3 = param_3;
  if (0 < param_3) {
    do {
      lVar2 = FUN_140010160((longlong)param_1);
      if (lVar2 < 1) {
        sVar1 = (*(code *)PTR__guard_dispatch_icall_14005b538)(param_1,*(undefined2 *)param_2);
        if (sVar1 == -1) break;
        lVar2 = -1;
        uVar4 = 2;
      }
      else {
        lVar5 = lVar3;
        if (lVar2 <= lVar3) {
          lVar5 = lVar2;
        }
        uVar4 = lVar5 * 2;
        FUN_1400316b0(*(undefined8 **)param_1[8],param_2,uVar4);
        lVar2 = -lVar5;
        *(int *)param_1[0xb] = *(int *)param_1[0xb] - (int)lVar5;
        *(longlong *)param_1[8] = *(longlong *)param_1[8] + (longlong)(int)lVar5 * 2;
      }
      lVar3 = lVar3 + lVar2;
      param_2 = (undefined8 *)((longlong)param_2 + uVar4);
    } while (0 < lVar3);
  }
  return param_3 - lVar3;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000e050 @ 14000e050