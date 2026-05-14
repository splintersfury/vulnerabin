void __fastcall FUN_10017880(int param_1)

{
  uint uVar1;
  int iVar2;
  undefined1 uVar3;
  int iVar4;
  undefined1 *puVar5;
  uint uVar6;
  code *pcVar7;
  char cVar8;
  int *piVar9;
  undefined4 uVar10;
  char *pcVar11;
  undefined1 auStack_3c [4];
  undefined4 auStack_38 [4];
  char *pcStack_28;
  int *piStack_24;
  int *piStack_20;
  int iStack_1c;
  undefined1 local_18 [4];
  int *local_14 [2];
  uint local_c;
  
  local_c = DAT_10069054 ^ (uint)auStack_3c;
  iVar4 = *(int *)(*(int *)(param_1 + 8) + -4);
  if (iVar4 != 0) {
    local_14[0] = (int *)((*(int *)(param_1 + 8) - *(int *)(param_1 + 4) >> 2) + -1);
    local_18[0] = 1;
    if (*(int **)(param_1 + 0x5c) == (int *)0x0) {
      FUN_1002c837();
      pcVar7 = (code *)swi(3);
      (*pcVar7)();
      return;
    }
    cVar8 = (**(code **)(**(int **)(param_1 + 0x5c) + 8))(local_14,local_18,iVar4);
    if (cVar8 == '\0') {
      FUN_10011220(&pcStack_28,(undefined1 *)(param_1 + 0x68));
      puVar5 = *(undefined1 **)(*(int *)(param_1 + 8) + -4);
      uVar3 = *puVar5;
      *puVar5 = pcStack_28._0_1_;
      pcStack_28 = (char *)CONCAT31(pcStack_28._1_3_,uVar3);
      iVar4 = *(int *)(puVar5 + 0xc);
      piVar9 = *(int **)(puVar5 + 8);
      *(int *)(puVar5 + 0xc) = iStack_1c;
      *(int **)(puVar5 + 8) = piStack_20;
      piStack_20 = piVar9;
      iStack_1c = iVar4;
      FUN_1000e760((char *)&pcStack_28);
    }
  }
  *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + -4;
  uVar6 = *(uint *)(param_1 + 0x1c);
  if (((int)uVar6 < 0) && (uVar6 != 0)) {
    iVar4 = -((~uVar6 >> 5) * 4 + 4);
  }
  else {
    iVar4 = (uVar6 >> 5) * 4;
  }
  uVar1 = (uVar6 & 0x1f) - 1;
  if ((uVar6 & 0x1f) == 0) {
    iVar2 = -((~uVar1 >> 5) * 4 + 4);
  }
  else {
    iVar2 = (uVar1 >> 5) * 4;
  }
  FUN_10018550((void *)(param_1 + 0x10),(int *)local_14,*(int *)(param_1 + 0x10) + iVar4 + iVar2,
               uVar1 & 0x1f);
  if (((*(int *)(param_1 + 4) == *(int *)(param_1 + 8)) ||
      (pcVar11 = *(char **)(*(int *)(param_1 + 8) + -4), pcVar11 == (char *)0x0)) ||
     (*pcVar11 != '\x01')) goto LAB_10017ae4;
  cVar8 = *pcVar11;
  piStack_24 = (int *)0x0;
  piStack_20 = (int *)0x0;
  if (cVar8 == '\x01') {
LAB_10017a17:
    iStack_1c = -0x80000000;
    piStack_24 = *(int **)**(undefined4 **)(pcVar11 + 8);
  }
  else if (cVar8 == '\x02') {
LAB_10017a0c:
    iStack_1c = -0x80000000;
    piStack_20 = (int *)**(int **)(pcVar11 + 8);
  }
  else if (cVar8 == '\0') {
    iStack_1c = 1;
  }
  else {
    if (cVar8 == '\x01') goto LAB_10017a17;
    if (cVar8 == '\x02') goto LAB_10017a0c;
    iStack_1c = 0;
  }
  pcStack_28 = pcVar11;
  piVar9 = FUN_100184e0(pcVar11,auStack_38);
  uVar10 = FUN_10018200(&pcStack_28,piVar9);
  if ((char)uVar10 != '\0') {
    while( true ) {
      pcVar11 = FUN_100182c0(&pcStack_28);
      if (*pcVar11 == '\b') break;
      if (*pcStack_28 == '\x01') {
        local_14[0] = piStack_24;
        std::
        _Tree_unchecked_const_iterator<class_std::_Tree_val<struct_std::_Tree_simple_types<unsigned_int>_>,struct_std::_Iterator_base0>
        ::operator++((_Tree_unchecked_const_iterator<class_std::_Tree_val<struct_std::_Tree_simple_types<unsigned_int>_>,struct_std::_Iterator_base0>
                      *)local_14);
        piStack_24 = local_14[0];
      }
      else if (*pcStack_28 == '\x02') {
        piStack_20 = piStack_20 + 4;
      }
      else {
        iStack_1c = iStack_1c + 1;
      }
      piVar9 = FUN_100184e0(*(void **)(*(int *)(param_1 + 8) + -4),auStack_38);
      uVar10 = FUN_10018200(&pcStack_28,piVar9);
      if ((char)uVar10 == '\0') {
        FUN_1002e315(local_c ^ (uint)auStack_3c);
        return;
      }
    }
    FUN_10019510(*(void **)(*(int *)(param_1 + 8) + -4),auStack_38,pcStack_28,piStack_24,piStack_20,
                 iStack_1c);
  }
LAB_10017ae4:
  FUN_1002e315(local_c ^ (uint)auStack_3c);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10017b00 @ 10017b00