void FUN_14001f420(longlong param_1,longlong param_2)

{
  undefined1 *puVar1;
  undefined1 *puVar2;
  undefined1 *puVar3;
  undefined1 uVar4;
  undefined1 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  longlong lVar9;
  undefined8 uVar10;
  undefined8 uVar11;
  undefined1 *puVar12;
  undefined1 *puVar13;
  undefined8 uVar14;
  undefined8 uVar15;
  undefined8 uVar16;
  int iVar17;
  
  if (param_1 != param_2) {
    lVar9 = *(longlong *)(param_1 + 0x80);
    uVar10 = *(undefined8 *)(param_1 + 0x68);
    uVar4 = *(undefined1 *)(param_1 + 0x71);
    uVar5 = *(undefined1 *)(param_1 + 0x7c);
    uVar11 = *(undefined8 *)(param_1 + 0x74);
    puVar12 = (undefined1 *)**(undefined8 **)(param_1 + 0x18);
    puVar13 = (undefined1 *)**(undefined8 **)(param_1 + 0x38);
    puVar1 = (undefined1 *)(param_1 + 0x70);
    uVar14 = **(undefined8 **)(param_1 + 0x20);
    uVar15 = **(undefined8 **)(param_1 + 0x40);
    uVar6 = **(undefined4 **)(param_1 + 0x58);
    uVar7 = **(undefined4 **)(param_1 + 0x50);
    FUN_14001d8d0(param_1,*(longlong *)(param_2 + 0x80),(uint)(*(longlong *)(param_2 + 0x80) != 0));
    puVar2 = (undefined1 *)(param_2 + 0x70);
    uVar16 = **(undefined8 **)(param_2 + 0x40);
    uVar8 = **(undefined4 **)(param_2 + 0x58);
    **(undefined8 **)(param_1 + 0x20) = **(undefined8 **)(param_2 + 0x20);
    **(undefined8 **)(param_1 + 0x40) = uVar16;
    **(undefined4 **)(param_1 + 0x58) = uVar8;
    if ((undefined1 *)**(undefined8 **)(param_2 + 0x18) == puVar2) {
      puVar3 = (undefined1 *)**(undefined8 **)(param_2 + 0x38);
      **(longlong **)(param_1 + 0x18) = (longlong)puVar1;
      if (puVar3 == puVar2) {
        **(longlong **)(param_1 + 0x38) = (longlong)puVar1;
        iVar17 = (int)puVar1;
      }
      else {
        **(longlong **)(param_1 + 0x38) = param_1 + 0x71;
        iVar17 = (int)(param_1 + 0x71);
      }
      iVar17 = ((int)param_1 - iVar17) + 0x71;
    }
    else {
      uVar16 = **(undefined8 **)(param_2 + 0x38);
      iVar17 = **(int **)(param_2 + 0x50);
      **(undefined8 **)(param_1 + 0x18) = (undefined1 *)**(undefined8 **)(param_2 + 0x18);
      **(undefined8 **)(param_1 + 0x38) = uVar16;
    }
    puVar3 = (undefined1 *)(param_2 + 0x71);
    **(int **)(param_1 + 0x50) = iVar17;
    *(undefined8 *)(param_1 + 0x68) = *(undefined8 *)(param_2 + 0x68);
    *(undefined8 *)(param_1 + 0x74) = *(undefined8 *)(param_2 + 0x74);
    *(undefined1 *)(param_1 + 0x71) = *puVar3;
    *(undefined1 *)(param_1 + 0x7c) = *(undefined1 *)(param_2 + 0x7c);
    FUN_14001d8d0(param_2,lVar9,(uint)(lVar9 != 0));
    **(undefined8 **)(param_2 + 0x20) = uVar14;
    **(undefined8 **)(param_2 + 0x40) = uVar15;
    **(undefined4 **)(param_2 + 0x58) = uVar6;
    if (puVar12 == puVar1) {
      **(longlong **)(param_2 + 0x18) = (longlong)puVar2;
      if (puVar13 == puVar1) {
        **(longlong **)(param_2 + 0x38) = (longlong)puVar2;
        iVar17 = (int)puVar2;
      }
      else {
        **(longlong **)(param_2 + 0x38) = (longlong)puVar3;
        iVar17 = (int)puVar3;
      }
      **(int **)(param_2 + 0x50) = ((int)param_2 - iVar17) + 0x71;
    }
    else {
      **(longlong **)(param_2 + 0x18) = (longlong)puVar12;
      **(undefined8 **)(param_2 + 0x38) = puVar13;
      **(undefined4 **)(param_2 + 0x50) = uVar7;
    }
    *(undefined8 *)(param_2 + 0x68) = uVar10;
    *(undefined8 *)(param_2 + 0x74) = uVar11;
    *puVar3 = uVar4;
    *(undefined1 *)(param_2 + 0x7c) = uVar5;
    uVar10 = *(undefined8 *)(param_1 + 0x88);
    *(undefined8 *)(param_1 + 0x88) = *(undefined8 *)(param_2 + 0x88);
    *(undefined8 *)(param_2 + 0x88) = uVar10;
    uVar10 = *(undefined8 *)(param_1 + 0x90);
    *(undefined8 *)(param_1 + 0x90) = *(undefined8 *)(param_2 + 0x90);
    *(undefined8 *)(param_2 + 0x90) = uVar10;
    uVar4 = *puVar1;
    *puVar1 = *puVar2;
    *puVar2 = uVar4;
    uVar10 = *(undefined8 *)(param_1 + 0x60);
    *(undefined8 *)(param_1 + 0x60) = *(undefined8 *)(param_2 + 0x60);
    *(undefined8 *)(param_2 + 0x60) = uVar10;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001f6d0 @ 14001f6d0