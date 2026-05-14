undefined4 __fastcall FUN_100177a0(int param_1)

{
  int *piVar1;
  char *pcVar2;
  undefined4 uVar3;
  code *pcVar4;
  char cVar5;
  undefined4 uVar6;
  int iVar7;
  char local_1c [8];
  undefined4 local_14;
  undefined4 local_10;
  int local_c;
  undefined1 local_8 [4];
  
  iVar7 = *(int *)(*(int *)(param_1 + 8) + -4);
  if (iVar7 != 0) {
    local_c = (*(int *)(param_1 + 8) - *(int *)(param_1 + 4) >> 2) + -1;
    local_8[0] = 3;
    if (*(int **)(param_1 + 0x5c) == (int *)0x0) {
      FUN_1002c837();
      pcVar4 = (code *)swi(3);
      uVar6 = (*pcVar4)();
      return uVar6;
    }
    cVar5 = (**(code **)(**(int **)(param_1 + 0x5c) + 8))(&local_c,local_8,iVar7);
    if (cVar5 == '\0') {
      FUN_10011220(local_1c,(undefined1 *)(param_1 + 0x68));
      pcVar2 = *(char **)(*(int *)(param_1 + 8) + -4);
      cVar5 = *pcVar2;
      *pcVar2 = local_1c[0];
      uVar6 = *(undefined4 *)(pcVar2 + 0xc);
      uVar3 = *(undefined4 *)(pcVar2 + 8);
      *(undefined4 *)(pcVar2 + 0xc) = local_10;
      *(undefined4 *)(pcVar2 + 8) = local_14;
      local_1c[0] = cVar5;
      local_14 = uVar3;
      local_10 = uVar6;
      FUN_1000e760(local_1c);
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + -4;
      FUN_10017fb0((int *)(param_1 + 0x10));
      iVar7 = *(int *)(param_1 + 4);
      if (iVar7 != *(int *)(param_1 + 8)) {
        iVar7 = *(int *)(param_1 + 8);
        if (**(char **)(iVar7 + -4) == '\x02') {
          iVar7 = *(int *)(*(char **)(iVar7 + -4) + 8);
          uVar6 = FUN_1000e760((char *)(*(int *)(iVar7 + 4) + -0x10));
          piVar1 = (int *)(iVar7 + 4);
          *piVar1 = *piVar1 + -0x10;
          return CONCAT31((int3)((uint)uVar6 >> 8),1);
        }
      }
      goto LAB_10017868;
    }
  }
  *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + -4;
  iVar7 = FUN_10017fb0((int *)(param_1 + 0x10));
LAB_10017868:
  return CONCAT31((int3)((uint)iVar7 >> 8),1);
}


// FUNCTION_END

// FUNCTION_START: FUN_10017880 @ 10017880