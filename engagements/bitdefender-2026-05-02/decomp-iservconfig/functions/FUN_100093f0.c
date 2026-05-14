undefined4 __fastcall FUN_100093f0(int *param_1)

{
  _Mtx_internal_imp_t *p_Var1;
  char cVar2;
  undefined4 *puVar3;
  int *piVar4;
  code *pcVar5;
  int *piVar6;
  int iVar7;
  uint uVar8;
  int *piVar9;
  undefined4 uVar10;
  ushort *******pppppppuVar11;
  ushort *puVar12;
  int *local_54;
  int local_50;
  int *local_4c;
  undefined4 *local_48;
  int *local_44;
  int *local_40;
  ushort ******local_3c;
  int iStack_38;
  int iStack_34;
  int iStack_30;
  uint local_2c;
  uint uStack_28;
  uint local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  uint local_14;
  
  puStack_20 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1004e1cd;
  local_1c = ExceptionList;
  ExceptionList = &local_1c;
  p_Var1 = (_Mtx_internal_imp_t *)(param_1 + 3);
  local_40 = param_1;
  iVar7 = __Mtx_lock(p_Var1);
  if (iVar7 != 0) {
    FUN_1002d2dd(iVar7);
LAB_1000967a:
    FUN_10001840();
LAB_1000967f:
    FUN_10032f7f();
    pcVar5 = (code *)swi(3);
    uVar10 = (*pcVar5)();
    return uVar10;
  }
  param_1[2] = param_1[2] + 1;
  if (1 < (uint)param_1[2]) {
    __Mtx_unlock((int)p_Var1);
    ExceptionList = local_1c;
    return 0;
  }
  __Mtx_unlock((int)p_Var1);
  FUN_10005210();
  local_48 = (undefined4 *)operator_new(0x10);
  *local_48 = 0;
  local_48[1] = 0;
  local_48[2] = 0;
  local_48[3] = 0;
  *local_48 = BDExportedObject<class_ProductInfo,1>::vftable;
  local_48[1] = 0;
  local_48[2] = 0;
  local_48[3] = 0;
  local_14 = 0;
  local_2c = 0;
  uStack_28 = 7;
  local_3c = (ushort ******)0x0;
  FUN_10001d40(&local_3c,(uint *)L"productinfo",0xb);
  local_14 = CONCAT31(local_14._1_3_,1);
  FUN_10009bc0(param_1,(int *)&local_54,(ushort *)&local_3c);
  if (*(char *)((int)local_4c + 0xd) == '\0') {
    puVar12 = (ushort *)(local_4c + 4);
    local_24 = local_4c[8];
    if (7 < (uint)local_4c[9]) {
      puVar12 = *(ushort **)puVar12;
    }
    pppppppuVar11 = &local_3c;
    if (7 < uStack_28) {
      pppppppuVar11 = (ushort *******)local_3c;
    }
    uVar8 = local_2c;
    if (local_24 < local_2c) {
      uVar8 = local_24;
    }
    iVar7 = FUN_10009c60((ushort *)pppppppuVar11,puVar12,uVar8);
    param_1 = local_40;
    if (iVar7 == 0) {
      if (local_2c < local_24) goto LAB_10009536;
    }
    else if (iVar7 < 0) goto LAB_10009536;
  }
  else {
LAB_10009536:
    if (param_1[1] == 0x5d1745d) goto LAB_1000967a;
    iVar7 = *param_1;
    local_14 = CONCAT31(local_14._1_3_,2);
    local_40 = (int *)0x0;
    local_44 = param_1;
    piVar9 = (int *)operator_new(0x2c);
    piVar9[4] = 0;
    piVar9[8] = 0;
    piVar9[9] = 0;
    piVar9[4] = (int)local_3c;
    piVar9[5] = iStack_38;
    piVar9[6] = iStack_34;
    piVar9[7] = iStack_30;
    *(ulonglong *)(piVar9 + 8) = CONCAT44(uStack_28,local_2c);
    local_3c = (ushort ******)((uint)local_3c & 0xffff0000);
    local_2c = 0;
    uStack_28 = 7;
    piVar9[10] = 0;
    *piVar9 = iVar7;
    piVar9[1] = iVar7;
    piVar9[2] = iVar7;
    *(undefined2 *)(piVar9 + 3) = 0;
    local_4c = Insert_node(param_1,local_54,local_50,piVar9);
  }
  puVar3 = (undefined4 *)local_4c[10];
  local_4c[10] = (int)local_48;
  if (puVar3 != (undefined4 *)0x0) {
    (**(code **)*puVar3)(1);
  }
  local_14 = local_14 & 0xffffff00;
  if (7 < uStack_28) {
    pppppppuVar11 = (ushort *******)local_3c;
    if ((0xfff < uStack_28 * 2 + 2) &&
       (pppppppuVar11 = (ushort *******)local_3c[-1],
       0x1f < (uint)((int)local_3c + (-4 - (int)pppppppuVar11)))) goto LAB_1000967f;
    FUN_1002e346(pppppppuVar11);
  }
  local_14 = 0xffffffff;
  piVar9 = *(int **)*param_1;
  if (piVar9 != (int *)*param_1) {
    do {
      (**(code **)(*(int *)piVar9[10] + 4))();
      piVar4 = (int *)piVar9[2];
      if (*(char *)((int)piVar4 + 0xd) == '\0') {
        cVar2 = *(char *)(*piVar4 + 0xd);
        piVar9 = piVar4;
        piVar4 = (int *)*piVar4;
        while (cVar2 == '\0') {
          cVar2 = *(char *)(*piVar4 + 0xd);
          piVar9 = piVar4;
          piVar4 = (int *)*piVar4;
        }
      }
      else {
        cVar2 = *(char *)(piVar9[1] + 0xd);
        piVar6 = (int *)piVar9[1];
        piVar4 = piVar9;
        while ((piVar9 = piVar6, cVar2 == '\0' && (piVar4 == (int *)piVar9[2]))) {
          cVar2 = *(char *)(piVar9[1] + 0xd);
          piVar6 = (int *)piVar9[1];
          piVar4 = piVar9;
        }
      }
    } while (piVar9 != (int *)*param_1);
  }
  ExceptionList = local_1c;
  return 0;
}


// FUNCTION_END

// FUNCTION_START: FUN_10009690 @ 10009690