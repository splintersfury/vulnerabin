void FUN_14001c5c0(longlong param_1,int param_2)

{
  ulonglong uVar1;
  char *pcVar2;
  longlong lVar3;
  undefined8 uVar4;
  int iVar5;
  size_t sVar6;
  size_t _Count;
  char cVar7;
  undefined1 auStack_98 [32];
  undefined8 *local_78;
  undefined1 *local_70;
  ulonglong *local_68;
  longlong *local_60;
  longlong local_48;
  undefined8 local_40;
  char local_38;
  undefined1 local_37 [7];
  undefined1 local_30 [32];
  ulonglong local_10;
  
  local_10 = DAT_14007a060 ^ (ulonglong)auStack_98;
  if (param_2 != -1) {
    uVar1 = **(ulonglong **)(param_1 + 0x40);
    cVar7 = (char)param_2;
    if (uVar1 != 0) {
      iVar5 = **(int **)(param_1 + 0x58);
      if (uVar1 < uVar1 + (longlong)iVar5) {
        **(int **)(param_1 + 0x58) = iVar5 + -1;
        pcVar2 = (char *)**(longlong **)(param_1 + 0x40);
        **(longlong **)(param_1 + 0x40) = (longlong)(pcVar2 + 1);
        *pcVar2 = cVar7;
        goto LAB_14001c740;
      }
    }
    if (*(longlong *)(param_1 + 0x80) != 0) {
      if (**(longlong **)(param_1 + 0x18) == param_1 + 0x70) {
        lVar3 = *(longlong *)(param_1 + 0x88);
        uVar4 = *(undefined8 *)(param_1 + 0x90);
        **(longlong **)(param_1 + 0x18) = lVar3;
        **(longlong **)(param_1 + 0x38) = lVar3;
        **(int **)(param_1 + 0x50) = (int)uVar4 - (int)lVar3;
      }
      if (*(longlong *)(param_1 + 0x68) != 0) {
        local_60 = &local_48;
        local_68 = &local_10;
        local_70 = local_30;
        local_78 = &local_40;
        local_38 = cVar7;
        iVar5 = (*(code *)PTR__guard_dispatch_icall_14005b538)
                          (*(longlong *)(param_1 + 0x68),param_1 + 0x74,&local_38,local_37);
        if ((iVar5 == 0) || (iVar5 == 1)) {
          _Count = local_48 - (longlong)local_30;
          if ((_Count == 0) ||
             (sVar6 = fwrite(local_30,1,_Count,*(FILE **)(param_1 + 0x80)), _Count == sVar6)) {
            *(undefined1 *)(param_1 + 0x71) = 1;
          }
          goto LAB_14001c740;
        }
        cVar7 = local_38;
        if (iVar5 != 3) goto LAB_14001c740;
      }
      fputc((int)cVar7,*(FILE **)(param_1 + 0x80));
    }
  }
LAB_14001c740:
  FUN_14002f160(local_10 ^ (ulonglong)auStack_98);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001c770 @ 14001c770