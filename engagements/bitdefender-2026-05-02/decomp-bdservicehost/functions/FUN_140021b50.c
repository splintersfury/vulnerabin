void FUN_140021b50(char *param_1,undefined8 *param_2,undefined8 param_3)

{
  char cVar1;
  ulonglong uVar2;
  uint uVar3;
  char *pcVar4;
  char *pcVar5;
  longlong *plVar6;
  undefined8 *puVar7;
  undefined8 *puVar8;
  undefined8 *_Buf2;
  longlong lVar9;
  longlong lVar10;
  ulonglong uVar11;
  ulonglong uVar12;
  char cVar13;
  bool bVar14;
  undefined1 auStack_178 [32];
  undefined8 *local_158;
  undefined8 *local_150;
  undefined8 *local_148;
  undefined8 local_140;
  longlong local_138 [7];
  undefined8 local_100 [7];
  undefined8 local_c8 [7];
  undefined8 local_90 [7];
  longlong local_58 [6];
  
  local_58[4] = DAT_14007a060 ^ (ulonglong)auStack_178;
  local_150 = param_2;
  local_140 = param_3;
  if (*param_1 != '\x01') {
    pcVar5 = FUN_14001ddd0(param_1);
    plVar6 = FUN_14000e950(local_138,(undefined8 *)pcVar5);
    puVar7 = FUN_140011fa0(local_58,(undefined8 *)"cannot use value() with ",plVar6,param_2);
    FUN_1400190c0(local_100,0x132,puVar7);
                    /* WARNING: Subroutine does not return */
    _CxxThrowException(local_100,(ThrowInfo *)&DAT_140077cc0);
  }
  local_58[1] = 0;
  local_58[2] = 0;
  local_58[3] = 0;
  lVar9 = -0x8000000000000000;
  lVar10 = -0x8000000000000000;
  cVar13 = *param_1;
  if (cVar13 == '\x01') {
LAB_140021bde:
    pcVar5 = (char *)0x0;
  }
  else {
    if (cVar13 != '\x02') {
      if (cVar13 != '\x01') {
        if (cVar13 == '\x02') goto LAB_140021c53;
        lVar10 = 1;
      }
      goto LAB_140021bde;
    }
LAB_140021c53:
    pcVar5 = *(char **)(*(longlong *)(param_1 + 8) + 8);
  }
  local_158 = (undefined8 *)**(longlong **)(param_1 + 8);
  local_148 = local_158;
  if (*(char *)((longlong)local_158[1] + 0x19) == '\0') {
    uVar12 = param_2[2];
    puVar7 = (undefined8 *)local_158[1];
    do {
      puVar8 = puVar7 + 4;
      _Buf2 = param_2;
      if (0xf < (ulonglong)param_2[3]) {
        _Buf2 = (undefined8 *)*param_2;
      }
      uVar2 = puVar7[6];
      if (0xf < (ulonglong)puVar7[7]) {
        puVar8 = (undefined8 *)*puVar8;
      }
      uVar11 = uVar2;
      if (uVar12 < uVar2) {
        uVar11 = uVar12;
      }
      uVar3 = memcmp(puVar8,_Buf2,uVar11);
      uVar12 = param_2[2];
      if (uVar3 == 0) {
        if (uVar2 < uVar12) {
          uVar3 = 0xffffffff;
        }
        else {
          uVar3 = (uint)(uVar12 < uVar2);
        }
      }
      if ((int)uVar3 < 0) {
        puVar8 = (undefined8 *)puVar7[2];
      }
      else {
        puVar8 = (undefined8 *)*puVar7;
        local_158 = puVar7;
      }
      puVar7 = puVar8;
    } while (*(char *)((longlong)puVar8 + 0x19) == '\0');
    cVar13 = *param_1;
  }
  if (*(char *)((longlong)local_158 + 0x19) == '\0') {
    puVar7 = local_158 + 4;
    uVar12 = local_158[6];
    if (0xf < (ulonglong)local_158[7]) {
      puVar7 = (undefined8 *)*puVar7;
    }
    uVar2 = local_150[2];
    puVar8 = local_150;
    if (0xf < (ulonglong)local_150[3]) {
      puVar8 = (undefined8 *)*local_150;
    }
    uVar11 = uVar2;
    if (uVar12 < uVar2) {
      uVar11 = uVar12;
    }
    uVar3 = memcmp(puVar8,puVar7,uVar11);
    if (uVar3 == 0) {
      if (uVar2 < uVar12) {
        uVar3 = 0xffffffff;
      }
      else {
        uVar3 = (uint)(uVar12 < uVar2);
      }
    }
    puVar7 = local_158;
    if ((int)uVar3 < 0) goto LAB_140021cee;
  }
  else {
LAB_140021cee:
    puVar7 = local_148;
  }
  local_58[1] = 0;
  local_58[2] = 0;
  local_58[3] = 0;
  cVar1 = *param_1;
  if (cVar1 == '\x01') {
LAB_140021d36:
    puVar8 = (undefined8 *)**(undefined8 **)(param_1 + 8);
  }
  else {
    if (cVar1 == '\x02') {
LAB_140021d28:
      pcVar4 = *(char **)(*(longlong *)(param_1 + 8) + 8);
      puVar8 = (undefined8 *)0x0;
      goto LAB_140021d41;
    }
    if (cVar1 == '\x01') goto LAB_140021d36;
    if (cVar1 == '\x02') goto LAB_140021d28;
    lVar9 = 1;
    puVar8 = (undefined8 *)0x0;
  }
  pcVar4 = (char *)0x0;
LAB_140021d41:
  if (cVar13 == '\x01') {
    bVar14 = puVar7 == puVar8;
  }
  else if (cVar13 == '\x02') {
    bVar14 = pcVar5 == pcVar4;
  }
  else {
    bVar14 = lVar10 == lVar9;
  }
  if (!bVar14) {
    if (cVar13 == '\0') {
      FUN_14000e950(local_58,(undefined8 *)"cannot get value");
      FUN_140018ed0(local_100,0xd6,local_58);
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_100,(ThrowInfo *)&DAT_140077d70);
    }
    if (cVar13 == '\x01') {
      pcVar5 = (char *)(puVar7 + 8);
    }
    else if ((cVar13 != '\x02') && (pcVar5 = param_1, lVar10 != 0)) {
      FUN_14000e950(local_58,(undefined8 *)"cannot get value");
      FUN_140018ed0(local_c8,0xd6,local_58);
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_c8,(ThrowInfo *)&DAT_140077d70);
    }
    if (*pcVar5 != '\x04') {
      pcVar5 = FUN_14001ddd0(pcVar5);
      plVar6 = FUN_14000e950(local_58,(undefined8 *)pcVar5);
      puVar7 = FUN_140011fa0(local_138,(undefined8 *)"type must be boolean, but is ",plVar6,puVar7);
      FUN_1400190c0(local_90,0x12e,puVar7);
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_90,(ThrowInfo *)&DAT_140077cc0);
    }
  }
  FUN_14002f160(local_58[4] ^ (ulonglong)auStack_178);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140021ed0 @ 140021ed0