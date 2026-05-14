void FUN_1001aba0(int *param_1,int *param_2,uint *param_3)

{
  char cVar1;
  char cVar2;
  int *piVar3;
  int *piVar4;
  int *piVar5;
  int *piVar6;
  uint uVar7;
  uint uVar8;
  
  if (*(char *)((int)param_2 + 0xd) != '\0') {
    if ((*(char *)(DAT_1006b658[1] + 0xd) != '\0') ||
       (uVar8 = *param_3, *(uint *)(DAT_1006b658[2] + 0x10) < uVar8)) {
      *param_1 = DAT_1006b658[2];
      *(undefined1 *)(param_1 + 2) = 0;
      param_1[1] = 0;
      return;
    }
    goto LAB_1001ad0c;
  }
  uVar8 = *param_3;
  uVar7 = param_2[4];
  if (param_2 == (int *)*DAT_1006b658) {
    if (uVar8 < uVar7) {
      *param_1 = (int)param_2;
      param_1[1] = 1;
      *(undefined1 *)(param_1 + 2) = 0;
      return;
    }
    goto LAB_1001ad0c;
  }
  if (uVar8 < uVar7) {
    piVar5 = (int *)*param_2;
    if (*(char *)((int)piVar5 + 0xd) == '\0') {
      cVar1 = *(char *)(piVar5[2] + 0xd);
      piVar6 = (int *)piVar5[2];
      while (cVar1 == '\0') {
        cVar1 = *(char *)(piVar6[2] + 0xd);
        piVar5 = piVar6;
        piVar6 = (int *)piVar6[2];
      }
    }
    else {
      cVar1 = *(char *)(param_2[1] + 0xd);
      piVar4 = (int *)param_2[1];
      piVar6 = param_2;
      while ((piVar5 = piVar4, cVar1 == '\0' && (piVar6 == (int *)*piVar5))) {
        cVar1 = *(char *)(piVar5[1] + 0xd);
        piVar4 = (int *)piVar5[1];
        piVar6 = piVar5;
      }
      if (*(char *)((int)piVar6 + 0xd) != '\0') {
        piVar5 = piVar6;
      }
    }
    if ((uint)piVar5[4] < uVar8) {
      cVar1 = *(char *)(piVar5[2] + 0xd);
      *(undefined1 *)(param_1 + 2) = 0;
      if (cVar1 != '\0') {
        *param_1 = (int)piVar5;
        param_1[1] = 0;
        return;
      }
      *param_1 = (int)param_2;
      param_1[1] = 1;
      return;
    }
    goto LAB_1001ad0c;
  }
  if (uVar8 <= uVar7) {
    *(undefined1 *)(param_1 + 2) = 1;
    goto LAB_1001ad8e;
  }
  piVar5 = (int *)param_2[2];
  cVar1 = *(char *)((int)piVar5 + 0xd);
  if (cVar1 == '\0') {
    cVar2 = *(char *)(*piVar5 + 0xd);
    piVar6 = (int *)*piVar5;
    while (cVar2 == '\0') {
      cVar2 = *(char *)(*piVar6 + 0xd);
      piVar5 = piVar6;
      piVar6 = (int *)*piVar6;
    }
LAB_1001acff:
    if ((*(char *)((int)piVar5 + 0xd) == '\0') && ((uint)piVar5[4] <= uVar8)) {
LAB_1001ad0c:
      piVar5 = (int *)DAT_1006b658[1];
      uVar7 = 0;
      cVar1 = *(char *)((int)piVar5 + 0xd);
      piVar6 = piVar5;
      piVar4 = DAT_1006b658;
      while (piVar3 = piVar5, cVar1 == '\0') {
        if (uVar8 <= (uint)piVar3[4]) {
          piVar5 = (int *)*piVar3;
          piVar4 = piVar3;
        }
        else {
          piVar5 = (int *)piVar3[2];
        }
        uVar7 = (uint)(uVar8 <= (uint)piVar3[4]);
        cVar1 = *(char *)((int)piVar5 + 0xd);
        piVar6 = piVar3;
      }
      if ((*(char *)((int)piVar4 + 0xd) == '\0') && ((uint)piVar4[4] <= uVar8)) {
        *param_1 = (int)piVar4;
        param_1[1] = 2;
        *(undefined1 *)(param_1 + 2) = 1;
        return;
      }
      *param_1 = (int)piVar6;
      param_1[1] = uVar7;
      *(undefined1 *)(param_1 + 2) = 0;
      return;
    }
  }
  else {
    piVar6 = (int *)param_2[1];
    piVar4 = param_2;
    piVar5 = piVar6;
    if (*(char *)((int)piVar6 + 0xd) == '\0') {
      do {
        piVar5 = piVar6;
        if (piVar4 != (int *)piVar6[2]) break;
        piVar5 = (int *)piVar6[1];
        piVar4 = piVar6;
        piVar6 = piVar5;
      } while (*(char *)((int)piVar5 + 0xd) == '\0');
      goto LAB_1001acff;
    }
  }
  *(undefined1 *)(param_1 + 2) = 0;
  if (cVar1 == '\0') {
    *param_1 = (int)piVar5;
    param_1[1] = 1;
    return;
  }
LAB_1001ad8e:
  *param_1 = (int)param_2;
  param_1[1] = 0;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001ada0 @ 1001ada0