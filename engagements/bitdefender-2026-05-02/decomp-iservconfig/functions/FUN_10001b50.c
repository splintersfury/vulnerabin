void FUN_10001b50(int *param_1,int *param_2,uint *param_3)

{
  char cVar1;
  char cVar2;
  uint uVar3;
  int *piVar4;
  int *piVar5;
  int *piVar6;
  uint uVar7;
  int local_14;
  int local_10;
  int local_c;
  int *local_8;
  
  if (*(char *)((int)param_2 + 0xd) != '\0') {
    if ((*(char *)(DAT_1006b644[1] + 0xd) != '\0') ||
       (uVar7 = *param_3, *(uint *)(DAT_1006b644[2] + 0x10) < uVar7)) {
      *param_1 = DAT_1006b644[2];
      *(undefined1 *)(param_1 + 2) = 0;
      param_1[1] = 0;
      return;
    }
    goto LAB_10001cbb;
  }
  uVar3 = param_2[4];
  uVar7 = *param_3;
  if (param_2 == (int *)*DAT_1006b644) {
    if (uVar7 < uVar3) {
      *param_1 = (int)param_2;
      param_1[1] = 1;
      *(undefined1 *)(param_1 + 2) = 0;
      return;
    }
    goto LAB_10001cbb;
  }
  if (uVar7 < uVar3) {
    piVar6 = (int *)*param_2;
    if (*(char *)((int)piVar6 + 0xd) == '\0') {
      cVar1 = *(char *)(piVar6[2] + 0xd);
      piVar5 = (int *)piVar6[2];
      while (cVar1 == '\0') {
        cVar1 = *(char *)(piVar5[2] + 0xd);
        piVar6 = piVar5;
        piVar5 = (int *)piVar5[2];
      }
    }
    else {
      cVar1 = *(char *)(param_2[1] + 0xd);
      piVar4 = (int *)param_2[1];
      piVar5 = param_2;
      while ((piVar6 = piVar4, cVar1 == '\0' && (local_8 = piVar6, piVar5 == (int *)*piVar6))) {
        cVar1 = *(char *)(piVar6[1] + 0xd);
        piVar4 = (int *)piVar6[1];
        piVar5 = piVar6;
      }
      if (*(char *)((int)piVar5 + 0xd) != '\0') {
        piVar6 = piVar5;
      }
    }
    if ((uint)piVar6[4] < uVar7) {
      cVar1 = *(char *)(piVar6[2] + 0xd);
      *(undefined1 *)(param_1 + 2) = 0;
      if (cVar1 == '\0') {
        *param_1 = (int)param_2;
        param_1[1] = 1;
        return;
      }
      *param_1 = (int)piVar6;
      param_1[1] = 0;
      return;
    }
    goto LAB_10001cbb;
  }
  if (uVar7 <= uVar3) {
    *(undefined1 *)(param_1 + 2) = 1;
    goto LAB_10001d2d;
  }
  piVar6 = (int *)param_2[2];
  cVar1 = *(char *)((int)piVar6 + 0xd);
  if (cVar1 == '\0') {
    cVar2 = *(char *)(*piVar6 + 0xd);
    piVar5 = (int *)*piVar6;
    while (cVar2 == '\0') {
      cVar2 = *(char *)(*piVar5 + 0xd);
      piVar6 = piVar5;
      piVar5 = (int *)*piVar5;
    }
LAB_10001cb0:
    if ((*(char *)((int)piVar6 + 0xd) == '\0') && ((uint)piVar6[4] <= uVar7)) {
LAB_10001cbb:
      FUN_10001890(&local_14,param_3);
      if ((*(char *)(local_c + 0xd) == '\0') && (*(uint *)(local_c + 0x10) <= uVar7)) {
        *param_1 = local_c;
        param_1[1] = 2;
        *(undefined1 *)(param_1 + 2) = 1;
        return;
      }
      *param_1 = local_14;
      param_1[1] = local_10;
      *(undefined1 *)(param_1 + 2) = 0;
      return;
    }
  }
  else {
    piVar5 = (int *)param_2[1];
    piVar4 = param_2;
    piVar6 = piVar5;
    if (*(char *)((int)piVar5 + 0xd) == '\0') {
      do {
        piVar6 = piVar5;
        if (piVar4 != (int *)piVar5[2]) break;
        piVar6 = (int *)piVar5[1];
        piVar4 = piVar5;
        piVar5 = piVar6;
      } while (*(char *)((int)piVar6 + 0xd) == '\0');
      goto LAB_10001cb0;
    }
  }
  *(undefined1 *)(param_1 + 2) = 0;
  if (cVar1 == '\0') {
    *param_1 = (int)piVar6;
    param_1[1] = 1;
    return;
  }
LAB_10001d2d:
  *param_1 = (int)param_2;
  param_1[1] = 0;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10001d40 @ 10001d40