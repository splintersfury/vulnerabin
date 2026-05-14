int * __fastcall FUN_1002b580(int *param_1,int *param_2,int *param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  int *piVar5;
  
  piVar5 = param_3;
  if (param_1 != param_2) {
    piVar4 = param_1;
    do {
      *piVar5 = 0;
      piVar5[4] = 0;
      *(undefined4 *)((int)param_3 + (0x14 - (int)param_1) + (int)piVar4) = 0;
      iVar1 = piVar4[1];
      iVar2 = piVar4[2];
      iVar3 = piVar4[3];
      *piVar5 = *piVar4;
      piVar5[1] = iVar1;
      piVar5[2] = iVar2;
      piVar5[3] = iVar3;
      *(undefined8 *)(piVar5 + 4) = *(undefined8 *)(piVar4 + 4);
      piVar5 = piVar5 + 6;
      piVar4[4] = 0;
      piVar4[5] = 7;
      *(undefined2 *)piVar4 = 0;
      piVar4 = piVar4 + 6;
    } while (piVar4 != param_2);
  }
  FUN_1002b510(piVar5,piVar5);
  return piVar5;
}


// FUNCTION_END

// FUNCTION_START: FUN_1002b5f0 @ 1002b5f0