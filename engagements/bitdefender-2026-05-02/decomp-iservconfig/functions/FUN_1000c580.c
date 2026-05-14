void __thiscall FUN_1000c580(void *this,int *param_1,ushort *param_2,wchar_t *param_3,uint *param_4)

{
  _Mtx_internal_imp_t *p_Var1;
  ushort uVar2;
  code *pcVar3;
  undefined4 *puVar4;
  wchar_t *pwVar5;
  uint *puVar6;
  undefined1 uVar7;
  int *piVar8;
  uint uVar9;
  int iVar10;
  undefined4 *puVar11;
  uint *********pppppppppuVar12;
  ushort *puVar13;
  undefined4 *puVar14;
  undefined4 *puVar15;
  bool bVar16;
  char cVar17;
  int local_4f4 [24];
  undefined **local_494 [18];
  _Mtx_internal_imp_t *local_44c;
  wchar_t *local_448;
  uint *local_444;
  undefined1 local_440 [1044];
  uint ********local_2c [4];
  uint local_1c;
  uint local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004e66f;
  local_10 = ExceptionList;
  local_14 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_448 = param_3;
  local_444 = param_4;
  FUN_1000c210(local_440,L"ProductInfo::GetStringCpy");
  local_8 = 0;
  piVar8 = FUN_100034b0(local_4f4,0x10,0x1005ec98);
  local_8 = CONCAT31(local_8._1_3_,1);
  bVar16 = (char)piVar8[0x12] == '\0';
  if (!bVar16) {
    FUN_10007f80(piVar8,"id=");
    bVar16 = (char)piVar8[0x12] == '\0';
  }
  if (!bVar16) {
    FUN_1001a980(piVar8,param_1);
  }
  FUN_10003240((int)local_494);
  local_8._0_1_ = 2;
  local_494[0] = std::ios_base::vftable;
  std::ios_base::_Ios_base_dtor((ios_base *)local_494);
  local_8._0_1_ = 0;
  if (local_444 == (uint *)0x0) goto LAB_1000c989;
  local_1c = 0;
  local_18 = 7;
  local_2c[0] = (uint ********)0x0;
  local_8._0_1_ = 3;
  uVar7 = (undefined1)local_8;
  local_8._0_1_ = 3;
  if (param_2 == (ushort *)0x0) {
LAB_1000c7c3:
    p_Var1 = (_Mtx_internal_imp_t *)((int)this + 4);
    local_44c = p_Var1;
    local_8._0_1_ = uVar7;
    iVar10 = __Mtx_lock(p_Var1);
    if (iVar10 == 0) {
      local_8._0_1_ = 7;
      puVar15 = *(undefined4 **)((int)this + 0x38);
      cVar17 = *(char *)((int)puVar15[1] + 0xd);
      puVar4 = puVar15;
      puVar14 = (undefined4 *)puVar15[1];
      while (cVar17 == '\0') {
        if ((int *)puVar14[4] < param_1) {
          puVar11 = (undefined4 *)puVar14[2];
          puVar14 = puVar4;
        }
        else {
          puVar11 = (undefined4 *)*puVar14;
        }
        puVar4 = puVar14;
        puVar14 = puVar11;
        cVar17 = *(char *)((int)puVar11 + 0xd);
      }
      if (((*(char *)((int)puVar4 + 0xd) == '\0') && ((int *)puVar4[4] <= param_1)) &&
         (puVar4 != puVar15)) {
        pppppppppuVar12 = (uint *********)(puVar4 + 5);
        if (local_2c != pppppppppuVar12) {
          if (7 < (uint)puVar4[10]) {
            pppppppppuVar12 = (uint *********)*pppppppppuVar12;
          }
          FUN_10001d40(local_2c,(uint *)pppppppppuVar12,puVar4[9]);
        }
        local_8._0_1_ = 3;
        __Mtx_unlock((int)p_Var1);
LAB_1000c7a3:
        puVar6 = local_444;
        pwVar5 = local_448;
        if (local_1c < *local_444) {
          pppppppppuVar12 = local_2c;
          if (7 < local_18) {
            pppppppppuVar12 = (uint *********)local_2c[0];
          }
          _wcscpy_s(local_448,*local_444,(wchar_t *)pppppppppuVar12);
          *puVar6 = local_1c + 1;
          piVar8 = FUN_100034b0(local_4f4,0x10,0x1005ec98);
          local_8._0_1_ = 8;
          if (((char)piVar8[0x12] != '\0') &&
             (FUN_10007f80(piVar8,"value="), (char)piVar8[0x12] != '\0')) {
            FUN_100082c0(piVar8,pwVar5);
          }
          FUN_10003240((int)local_494);
          local_8._0_1_ = 9;
          local_494[0] = std::ios_base::vftable;
          std::ios_base::_Ios_base_dtor((ios_base *)local_494);
        }
        else {
          *local_444 = local_1c + 1;
        }
      }
      else {
        puVar15 = *(undefined4 **)((int)this + 0x40);
        cVar17 = *(char *)((int)puVar15[1] + 0xd);
        puVar4 = puVar15;
        puVar14 = (undefined4 *)puVar15[1];
        while (cVar17 == '\0') {
          if ((int *)puVar14[4] < param_1) {
            puVar11 = (undefined4 *)puVar14[2];
            puVar14 = puVar4;
          }
          else {
            puVar11 = (undefined4 *)*puVar14;
          }
          puVar4 = puVar14;
          puVar14 = puVar11;
          cVar17 = *(char *)((int)puVar11 + 0xd);
        }
        if (((*(char *)((int)puVar4 + 0xd) == '\0') && ((int *)puVar4[4] <= param_1)) &&
           (puVar4 != puVar15)) {
          __Mtx_unlock((int)p_Var1);
        }
        else {
          cVar17 = FUN_1000d450(this,param_1,(undefined **)local_2c);
          local_8._0_1_ = 3;
          __Mtx_unlock((int)p_Var1);
          if (cVar17 != '\0') goto LAB_1000c7a3;
        }
      }
LAB_1000c93f:
      if (7 < local_18) {
        pppppppppuVar12 = (uint *********)local_2c[0];
        if ((0xfff < local_18 * 2 + 2) &&
           (pppppppppuVar12 = (uint *********)local_2c[0][-1],
           0x1f < (uint)((int)local_2c[0] + (-4 - (int)pppppppppuVar12)))) goto LAB_1000c9c0;
        FUN_1002e346(pppppppppuVar12);
      }
      local_1c = 0;
      local_18 = 7;
      local_2c[0] = (uint ********)((uint)local_2c[0] & 0xffff0000);
LAB_1000c989:
      FUN_1000c320((int)local_440);
      ExceptionList = local_10;
      FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
      return;
    }
  }
  else {
    puVar13 = &DAT_1005ecd0;
    do {
      uVar2 = *param_2;
      bVar16 = uVar2 < *puVar13;
      if (uVar2 != *puVar13) {
LAB_1000c6b6:
        uVar9 = -(uint)bVar16 | 1;
        goto LAB_1000c6bb;
      }
      if (uVar2 == 0) break;
      uVar2 = param_2[1];
      bVar16 = uVar2 < puVar13[1];
      if (uVar2 != puVar13[1]) goto LAB_1000c6b6;
      param_2 = param_2 + 2;
      puVar13 = puVar13 + 2;
    } while (uVar2 != 0);
    uVar9 = 0;
LAB_1000c6bb:
    if (uVar9 != 0) goto LAB_1000c7c3;
    piVar8 = FUN_100034b0(local_4f4,0x10,0x1005ec98);
    local_8._0_1_ = 4;
    if ((char)piVar8[0x12] != '\0') {
      FUN_100082c0(piVar8,L"selector=bdec");
    }
    FUN_10003240((int)local_494);
    local_8._0_1_ = 5;
    local_494[0] = std::ios_base::vftable;
    std::ios_base::_Ios_base_dtor((ios_base *)local_494);
    p_Var1 = (_Mtx_internal_imp_t *)((int)this + 4);
    local_8._0_1_ = 3;
    local_44c = p_Var1;
    iVar10 = __Mtx_lock(p_Var1);
    if (iVar10 == 0) {
      local_8._0_1_ = 6;
      puVar15 = *(undefined4 **)((int)this + 0x48);
      cVar17 = *(char *)((int)puVar15[1] + 0xd);
      puVar4 = puVar15;
      puVar14 = (undefined4 *)puVar15[1];
      while (cVar17 == '\0') {
        if ((int *)puVar14[4] < param_1) {
          puVar11 = (undefined4 *)puVar14[2];
          puVar14 = puVar4;
        }
        else {
          puVar11 = (undefined4 *)*puVar14;
        }
        puVar4 = puVar14;
        puVar14 = puVar11;
        cVar17 = *(char *)((int)puVar11 + 0xd);
      }
      if (((*(char *)((int)puVar4 + 0xd) == '\0') && ((int *)puVar4[4] <= param_1)) &&
         (puVar4 != puVar15)) {
        puVar15 = puVar4 + 5;
        if (7 < (uint)puVar4[10]) {
          puVar15 = (undefined4 *)*puVar15;
        }
        cVar17 = puVar15 != (undefined4 *)0x0;
      }
      else if (param_1 < (int *)0x7) {
        cVar17 = FUN_10003650(param_1,(uint *******)local_2c);
      }
      else {
        cVar17 = '\0';
      }
      local_8._0_1_ = 3;
      __Mtx_unlock((int)p_Var1);
      if (cVar17 == '\0') goto LAB_1000c93f;
      goto LAB_1000c7a3;
    }
    iVar10 = FUN_1002d2dd(iVar10);
  }
  FUN_1002d2dd(iVar10);
LAB_1000c9c0:
  FUN_10032f7f();
  pcVar3 = (code *)swi(3);
  (*pcVar3)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000c9d0 @ 1000c9d0