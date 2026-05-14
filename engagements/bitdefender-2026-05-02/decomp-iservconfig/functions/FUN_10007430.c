void __cdecl
FUN_10007430(undefined4 param_1,undefined4 *param_2,undefined4 param_3,int *param_4,short *param_5,
            int param_6)

{
  int iVar1;
  short *psVar2;
  short sVar3;
  
  if (param_6 != 0) {
    do {
      if (param_4 == (int *)0x0) {
LAB_10007494:
        param_3 = CONCAT31(param_3._1_3_,1);
      }
      else {
        sVar3 = *param_5;
        if (*(int *)param_4[8] == 0) {
LAB_1000747c:
          sVar3 = (**(code **)(*param_4 + 0xc))(sVar3);
        }
        else {
          iVar1 = *(int *)param_4[0xc];
          if (iVar1 < 1) goto LAB_1000747c;
          *(int *)param_4[0xc] = iVar1 + -1;
          psVar2 = *(short **)param_4[8];
          *(short **)param_4[8] = psVar2 + 1;
          *psVar2 = sVar3;
        }
        if (sVar3 == -1) goto LAB_10007494;
      }
      param_5 = param_5 + 1;
      param_6 = param_6 + -1;
    } while (param_6 != 0);
  }
  *param_2 = param_3;
  param_2[1] = param_4;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100074c0 @ 100074c0