undefined4 * __thiscall FUN_100239b0(void *this,undefined4 *param_1)

{
  char cVar1;
  undefined4 *puVar2;
  uint uVar3;
  char *extraout_ECX;
  byte *pbVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  FUN_100184e0(this,param_1);
  if (*extraout_ECX != '\x01') {
    return param_1;
  }
  puVar2 = (undefined4 *)**(int **)(extraout_ECX + 8);
  cVar1 = *(char *)((int)puVar2[1] + 0xd);
  puVar7 = puVar2;
  puVar6 = (undefined4 *)puVar2[1];
  while (cVar1 == '\0') {
    pbVar4 = (byte *)(puVar6 + 4);
    if (0xf < (uint)puVar6[9]) {
      pbVar4 = *(byte **)pbVar4;
    }
    uVar3 = FUN_100148a0(pbVar4,puVar6[8],(byte *)"encode_redirect",0xf);
    if ((int)uVar3 < 0) {
      puVar5 = (undefined4 *)puVar6[2];
      puVar6 = puVar7;
    }
    else {
      puVar5 = (undefined4 *)*puVar6;
    }
    puVar7 = puVar6;
    puVar6 = puVar5;
    cVar1 = *(char *)((int)puVar5 + 0xd);
  }
  if (*(char *)((int)puVar7 + 0xd) == '\0') {
    pbVar4 = (byte *)(puVar7 + 4);
    if (0xf < (uint)puVar7[9]) {
      pbVar4 = *(byte **)pbVar4;
    }
    uVar3 = FUN_100148a0(pbVar4,puVar7[8],(byte *)"encode_redirect",0xf);
    if ((int)uVar3 < 1) goto LAB_10023a3a;
  }
  puVar7 = puVar2;
LAB_10023a3a:
  param_1[1] = puVar7;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10023a50 @ 10023a50