void FUN_14001c1b0(longlong param_1)

{
  undefined1 *puVar1;
  undefined8 uVar2;
  code *pcVar3;
  uint uVar4;
  int iVar5;
  undefined8 *******pppppppuVar6;
  FILE *_File;
  longlong lVar7;
  undefined8 *******pppppppuVar8;
  ulonglong uVar9;
  undefined1 auStack_98 [32];
  longlong *local_78;
  undefined1 *local_70;
  undefined1 *local_68;
  undefined1 **local_60;
  longlong local_48;
  undefined1 *local_40;
  undefined1 local_38;
  undefined1 local_37 [7];
  undefined8 *******local_30 [2];
  ulonglong local_20;
  ulonglong local_18;
  ulonglong local_10;
  
  local_10 = DAT_14007a060 ^ (ulonglong)auStack_98;
  uVar9 = **(ulonglong **)(param_1 + 0x38);
  if (uVar9 != 0) {
    iVar5 = **(int **)(param_1 + 0x50);
    if (uVar9 < uVar9 + (longlong)iVar5) {
      **(int **)(param_1 + 0x50) = iVar5 + -1;
      **(longlong **)(param_1 + 0x38) = **(longlong **)(param_1 + 0x38) + 1;
      goto LAB_14001c432;
    }
  }
  if (*(longlong *)(param_1 + 0x80) != 0) {
    if (**(longlong **)(param_1 + 0x18) == param_1 + 0x70) {
      uVar2 = *(undefined8 *)(param_1 + 0x90);
      lVar7 = *(longlong *)(param_1 + 0x88);
      **(longlong **)(param_1 + 0x18) = lVar7;
      **(longlong **)(param_1 + 0x38) = lVar7;
      **(int **)(param_1 + 0x50) = (int)uVar2 - (int)lVar7;
    }
    _File = *(FILE **)(param_1 + 0x80);
    if (*(longlong *)(param_1 + 0x68) != 0) {
      local_20 = 0;
      local_18 = 0xf;
      local_30[0] = (undefined8 *******)0x0;
      while( true ) {
        uVar4 = fgetc(_File);
        uVar9 = local_20;
        if (uVar4 == 0xffffffff) goto LAB_14001c3f9;
        if (local_20 < local_18) {
          pppppppuVar6 = local_30;
          if (0xf < local_18) {
            pppppppuVar6 = local_30[0];
          }
          puVar1 = (undefined1 *)((longlong)pppppppuVar6 + local_20);
          local_20 = local_20 + 1;
          *puVar1 = (char)uVar4;
          *(undefined1 *)((longlong)pppppppuVar6 + uVar9 + 1) = 0;
        }
        else {
          FUN_1400137e0(local_30,(ulonglong)uVar4,local_18,(char)uVar4);
        }
        pppppppuVar6 = local_30;
        if (0xf < local_18) {
          pppppppuVar6 = local_30[0];
        }
        pppppppuVar8 = local_30;
        if (0xf < local_18) {
          pppppppuVar8 = local_30[0];
        }
        local_60 = &local_40;
        local_68 = local_37;
        local_70 = &local_38;
        local_78 = &local_48;
        iVar5 = (*(code *)PTR__guard_dispatch_icall_14005b538)
                          (*(undefined8 *)(param_1 + 0x68),param_1 + 0x74,pppppppuVar8,
                           local_20 + (longlong)pppppppuVar6);
        if ((iVar5 != 0) && (iVar5 != 1)) goto LAB_14001c3f9;
        if (local_40 != &local_38) break;
        pppppppuVar6 = local_30;
        if (0xf < local_18) {
          pppppppuVar6 = local_30[0];
        }
        uVar9 = local_48 - (longlong)pppppppuVar6;
        if (local_20 < (ulonglong)(local_48 - (longlong)pppppppuVar6)) {
          uVar9 = local_20;
        }
        pppppppuVar6 = local_30;
        if (0xf < local_18) {
          pppppppuVar6 = local_30[0];
        }
        local_20 = local_20 - uVar9;
        FUN_1400316b0(pppppppuVar6,(undefined8 *)((longlong)pppppppuVar6 + uVar9),local_20 + 1);
        _File = *(FILE **)(param_1 + 0x80);
      }
      pppppppuVar6 = local_30;
      if (0xf < local_18) {
        pppppppuVar6 = local_30[0];
      }
      lVar7 = (local_20 - local_48) + (longlong)pppppppuVar6;
      while (0 < lVar7) {
        lVar7 = lVar7 + -1;
        ungetc((int)*(char *)(lVar7 + local_48),*(FILE **)(param_1 + 0x80));
      }
LAB_14001c3f9:
      if (0xf < local_18) {
        if ((0xfff < local_18 + 1) &&
           (0x1f < (ulonglong)((longlong)local_30[0] + (-8 - (longlong)local_30[0][-1])))) {
          FUN_140035d28();
          pcVar3 = (code *)swi(3);
          (*pcVar3)();
          return;
        }
        FUN_14002f180();
      }
      goto LAB_14001c432;
    }
    fgetc(_File);
  }
LAB_14001c432:
  FUN_14002f160(local_10 ^ (ulonglong)auStack_98);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001c460 @ 14001c460