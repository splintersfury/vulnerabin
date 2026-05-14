longlong FUN_140014a20(undefined8 *param_1,undefined8 *param_2,longlong param_3)

{
  undefined8 *puVar1;
  undefined8 uVar2;
  undefined8 *puVar3;
  longlong lVar4;
  
  if (param_1 != param_2) {
    lVar4 = param_3 - (longlong)param_1;
    puVar3 = param_1 + 7;
    do {
      *(undefined8 *)(lVar4 + (longlong)puVar3) = 0;
      puVar1 = (undefined8 *)*puVar3;
      if (puVar1 != (undefined8 *)0x0) {
        if (puVar1 == puVar3 + -7) {
          uVar2 = (*(code *)PTR__guard_dispatch_icall_14005b538)(puVar1,param_3);
          *(undefined8 *)(lVar4 + (longlong)puVar3) = uVar2;
          puVar1 = (undefined8 *)*puVar3;
          if (puVar1 == (undefined8 *)0x0) goto LAB_140014aad;
          (*(code *)PTR__guard_dispatch_icall_14005b538)(puVar1,puVar1 != puVar3 + -7);
        }
        else {
          *(undefined8 **)(lVar4 + (longlong)puVar3) = puVar1;
        }
        *puVar3 = 0;
      }
LAB_140014aad:
      param_3 = param_3 + 0x40;
      puVar1 = puVar3 + 1;
      puVar3 = puVar3 + 8;
    } while (puVar1 != param_2);
  }
  return param_3;
}


// FUNCTION_END

// FUNCTION_START: FUN_140014ae0 @ 140014ae0