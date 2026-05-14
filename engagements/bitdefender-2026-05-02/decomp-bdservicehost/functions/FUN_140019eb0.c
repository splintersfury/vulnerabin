void FUN_140019eb0(char *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  double dVar1;
  byte bVar2;
  code *pcVar3;
  byte *pbVar4;
  double *pdVar5;
  undefined1 (*pauVar6) [16];
  undefined1 (*pauVar7) [16];
  longlong *plVar8;
  char *pcVar9;
  undefined8 *puVar10;
  double *pdVar11;
  uint uVar12;
  undefined8 uVar13;
  double dVar15;
  double dVar16;
  longlong local_148 [2];
  undefined8 local_138;
  ulonglong local_130;
  longlong local_128 [4];
  undefined8 local_108 [4];
  longlong local_e8 [7];
  longlong local_b0 [4];
  undefined8 local_90 [4];
  longlong local_70 [4];
  undefined8 local_50 [9];
  ulonglong uVar14;
  
  pdVar11 = (double *)0x0;
  local_138 = 0;
  local_130 = 0xf;
  local_148[0] = 0;
  uVar13 = 7;
  FUN_1400106a0(local_148,(undefined8 *)"version",7);
  pbVar4 = (byte *)FUN_14001cdf0(param_1,local_148,uVar13,param_4);
  bVar2 = *pbVar4;
  uVar12 = bVar2 - 5;
  uVar14 = (ulonglong)uVar12;
  if (uVar12 == 0) {
    pdVar5 = (double *)(pbVar4 + 8);
    if (1 < (byte)(bVar2 - 5)) {
      pdVar5 = pdVar11;
    }
    dVar1 = (double)(longlong)*pdVar5;
  }
  else {
    uVar12 = bVar2 - 6;
    uVar14 = (ulonglong)uVar12;
    if (uVar12 == 0) {
      pdVar5 = (double *)(pbVar4 + 8);
      if (bVar2 != 6) {
        pdVar5 = pdVar11;
      }
      dVar1 = *pdVar5;
      if ((longlong)dVar1 < 0) {
        dVar1 = (double)(ulonglong)dVar1;
      }
      else {
        dVar1 = (double)(longlong)dVar1;
      }
    }
    else {
      if (uVar12 != 1) {
        pcVar9 = FUN_14001ddd0(pbVar4);
        plVar8 = FUN_14000e950(local_128,(undefined8 *)pcVar9);
        puVar10 = FUN_140011fa0(local_108,(undefined8 *)"type must be number, but is ",plVar8,pbVar4
                               );
        FUN_1400190c0(local_e8,0x12e,puVar10);
                    /* WARNING: Subroutine does not return */
        _CxxThrowException(local_e8,(ThrowInfo *)&DAT_140077cc0);
      }
      pdVar5 = (double *)(pbVar4 + 8);
      if (bVar2 != 7) {
        pdVar5 = pdVar11;
      }
      dVar1 = *pdVar5;
    }
  }
  if (0xf < local_130) {
    if ((0xfff < local_130 + 1) && (0x1f < (local_148[0] - *(longlong *)(local_148[0] + -8)) - 8U))
    {
      FUN_140035d28();
      pcVar3 = (code *)swi(3);
      (*pcVar3)();
      return;
    }
    FUN_14002f180();
  }
  if (0.0 < dVar1) {
    dVar15 = floor(dVar1);
    dVar16 = floor(DAT_14006e160);
    if (dVar15 == dVar16) {
      return;
    }
  }
  pauVar6 = FUN_140018020((undefined1 (*) [16])local_108,DAT_14006e160,uVar14,pbVar4);
  pauVar7 = FUN_140018020((undefined1 (*) [16])local_128,dVar1,uVar14,pbVar4);
  plVar8 = FUN_14000e950(local_b0,(undefined8 *)"The JSON version \'");
  plVar8 = FUN_140021ab0(local_90,plVar8,(undefined8 *)pauVar7);
  plVar8 = FUN_1400219f0(local_70,plVar8,(undefined8 *)"\' is not accepted. It needs to be \'");
  plVar8 = FUN_140021ab0(local_50,plVar8,(undefined8 *)pauVar6);
  plVar8 = FUN_140021ad0(local_e8,plVar8,pauVar6);
  FUN_140001a40(local_148,plVar8);
                    /* WARNING: Subroutine does not return */
  _CxxThrowException(local_148,(ThrowInfo *)&DAT_140077818);
}


// FUNCTION_END

// FUNCTION_START: FUN_14001a110 @ 14001a110