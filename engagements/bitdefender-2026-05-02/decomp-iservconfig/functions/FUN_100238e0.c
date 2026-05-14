undefined4 * __thiscall FUN_100238e0(void *this,undefined4 *param_1,byte *param_2)

{
  byte bVar1;
  char cVar2;
  undefined4 *puVar3;
  byte *pbVar4;
  uint uVar5;
  char *extraout_ECX;
  byte *pbVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  FUN_100184e0(this,param_1);
  if (*extraout_ECX != '\x01') {
    return param_1;
  }
  puVar3 = (undefined4 *)**(int **)(extraout_ECX + 8);
  cVar2 = *(char *)((int)puVar3[1] + 0xd);
  puVar8 = puVar3;
  puVar7 = (undefined4 *)puVar3[1];
  while (cVar2 == '\0') {
    pbVar6 = (byte *)(puVar7 + 4);
    pbVar4 = param_2;
    do {
      bVar1 = *pbVar4;
      pbVar4 = pbVar4 + 1;
    } while (bVar1 != 0);
    if (0xf < (uint)puVar7[9]) {
      pbVar6 = *(byte **)pbVar6;
    }
    uVar5 = FUN_100148a0(pbVar6,puVar7[8],param_2,(int)pbVar4 - (int)(param_2 + 1));
    if ((int)uVar5 < 0) {
      puVar9 = (undefined4 *)puVar7[2];
      puVar7 = puVar8;
    }
    else {
      puVar9 = (undefined4 *)*puVar7;
    }
    puVar8 = puVar7;
    puVar7 = puVar9;
    cVar2 = *(char *)((int)puVar9 + 0xd);
  }
  if (*(char *)((int)puVar8 + 0xd) == '\0') {
    pbVar6 = (byte *)(puVar8 + 4);
    pbVar4 = param_2;
    do {
      bVar1 = *pbVar4;
      pbVar4 = pbVar4 + 1;
    } while (bVar1 != 0);
    if (0xf < (uint)puVar8[9]) {
      pbVar6 = *(byte **)pbVar6;
    }
    uVar5 = FUN_100148a0(pbVar6,puVar8[8],param_2,(int)pbVar4 - (int)(param_2 + 1));
    if ((int)uVar5 < 1) goto LAB_1002398d;
  }
  puVar8 = puVar3;
LAB_1002398d:
  param_1[1] = puVar8;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_100239b0 @ 100239b0