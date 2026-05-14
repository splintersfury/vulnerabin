void FUN_140003260(undefined8 param_1,LPSTR *****param_2,uint param_3)

{
  LPSTR ****pppppCVar1;
  code *pcVar2;
  ulonglong uVar3;
  LPSTR *****ppppppCVar4;
  DWORD DVar5;
  LPSTR ******pppppppCVar6;
  LPSTR *********ppppppppppCVar7;
  LPSTR **********pppppppppppCVar8;
  undefined1 (*pauVar9) [16];
  LPSTR ****pppppCVar10;
  ulonglong uVar11;
  LPSTR **********pppppppppppCVar12;
  LPSTR pCVar13;
  char *pcVar14;
  LPSTR **********pppppppppppCVar15;
  undefined1 auStackY_d8 [32];
  LPSTR ******local_98 [2];
  LPSTR local_88;
  ulonglong uStack_80;
  LPSTR **********local_78;
  LPSTR ****pppppCStack_70;
  LPSTR ****local_68;
  LPSTR ****pppppCStack_60;
  undefined1 local_58 [8];
  undefined4 local_50;
  undefined2 local_4c;
  undefined1 local_4a;
  char local_34 [4];
  ulonglong local_30;
  
  local_30 = DAT_14007a060 ^ (ulonglong)auStackY_d8;
  pppppppppppCVar12 = (LPSTR **********)0x0;
  local_68 = (LPSTR ****)0x0;
  pppppCStack_60 = (LPSTR ****)0xf;
  local_78 = (LPSTR **********)0x0;
  local_58 = (undefined1  [8])param_2;
  FUN_140010530((undefined1 (*) [16])&local_78,0x7fff,0);
  pppppppppppCVar8 = (LPSTR **********)&local_78;
  if ((LPSTR ****)0xf < pppppCStack_60) {
    pppppppppppCVar8 = local_78;
  }
  DVar5 = FormatMessageA(0x1200,(LPCVOID)0x0,param_3,0,(LPSTR)pppppppppppCVar8,0x7fff,(va_list *)0x0
                        );
  if (DVar5 != 0) {
    pppppCVar10 = (LPSTR ****)(ulonglong)DVar5;
    if (local_68 < pppppCVar10) {
      uVar11 = (longlong)pppppCVar10 - (longlong)local_68;
      if ((ulonglong)((longlong)pppppCStack_60 - (longlong)local_68) < uVar11) {
        FUN_140013950(&local_78,uVar11,pppppCStack_60,uVar11,0);
      }
      else {
        pppppppppppCVar8 = (LPSTR **********)&local_78;
        if ((LPSTR ****)0xf < pppppCStack_60) {
          pppppppppppCVar8 = local_78;
        }
        pauVar9 = (undefined1 (*) [16])((longlong)pppppppppppCVar8 + (longlong)local_68);
        local_68 = pppppCVar10;
        FUN_140031e00(pauVar9,0,uVar11);
        *(undefined1 *)((longlong)pauVar9 + uVar11) = 0;
      }
    }
    else {
      pppppppppppCVar8 = (LPSTR **********)&local_78;
      if ((LPSTR ****)0xf < pppppCStack_60) {
        pppppppppppCVar8 = local_78;
      }
      local_68 = pppppCVar10;
      *(CHAR *)((longlong)pppppppppppCVar8 + (longlong)pppppCVar10) = '\0';
    }
    if ((LPSTR ****)0xf < pppppCStack_60) {
      if (local_68 < (LPSTR ****)0x10) {
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
        _Become_small((basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>
                       *)&local_78);
      }
      else {
        pppppCVar10 = (LPSTR ****)((ulonglong)local_68 | 0xf);
        if ((LPSTR ****)0x7fffffffffffffff < pppppCVar10) {
          pppppCVar10 = (LPSTR ****)0x7fffffffffffffff;
        }
        if (pppppCVar10 < pppppCStack_60) {
          pppppCVar1 = (LPSTR ****)((longlong)pppppCVar10 + 1);
          if (pppppCVar1 < (LPSTR ****)0x1000) {
            if (pppppCVar1 != (LPSTR ****)0x0) {
              pppppppppppCVar12 = (LPSTR **********)operator_new((__uint64)pppppCVar1);
            }
LAB_14000360f:
            FUN_1400316b0(pppppppppppCVar12,local_78,(longlong)local_68 + 1);
            if (((longlong)pppppCStack_60 + 1U < 0x1000) ||
               ((LPSTR)((longlong)local_78 + (-8 - (longlong)local_78[-1])) < (LPSTR)0x20)) {
              FUN_14002f180();
              local_78 = pppppppppppCVar12;
              pppppCStack_60 = pppppCVar10;
              goto LAB_140003657;
            }
          }
          else {
            if (pppppCVar10 + 5 <= pppppCVar1) goto LAB_14000369e;
            ppppppppppCVar7 = (LPSTR *********)operator_new((__uint64)(pppppCVar10 + 5));
            if (ppppppppppCVar7 != (LPSTR *********)0x0) {
              pppppppppppCVar12 =
                   (LPSTR **********)((longlong)ppppppppppCVar7 + 0x27U & 0xffffffffffffffe0);
              pppppppppppCVar12[-1] = ppppppppppCVar7;
              goto LAB_14000360f;
            }
          }
          FUN_140035d28();
          goto LAB_140003692;
        }
      }
    }
LAB_140003657:
    *param_2 = (LPSTR ****)local_78;
    param_2[1] = pppppCStack_70;
    param_2[2] = local_68;
    param_2[3] = pppppCStack_60;
    goto LAB_140003666;
  }
  local_58 = (undefined1  [8])0x206e776f6e6b6e75;
  local_50 = 0x6f727265;
  local_4c = 0x2072;
  local_4a = 0;
  pcVar14 = local_34 + 1;
  uVar11 = (ulonglong)param_3;
  do {
    pcVar14 = pcVar14 + -1;
    uVar3 = uVar11 / 10;
    *pcVar14 = (char)uVar11 + (char)uVar3 * -10 + '0';
    uVar11 = uVar3;
  } while ((int)uVar3 != 0);
  local_88 = (LPSTR)0x0;
  uStack_80 = 0xf;
  local_98[0] = (LPSTR ******)0x0;
  if (pcVar14 != local_34 + 1) {
    FUN_1400106a0((longlong *)local_98,(undefined8 *)pcVar14,
                  (ulonglong)(local_34 + (1 - (longlong)pcVar14)));
  }
  pppppppppppCVar8 = (LPSTR **********)0xffffffffffffffff;
  do {
    pppppppppppCVar8 = (LPSTR **********)((longlong)pppppppppppCVar8 + 1);
  } while (local_58[(longlong)pppppppppppCVar8] != '\0');
  if ((LPSTR **********)(uStack_80 - (longlong)local_88) < pppppppppppCVar8) {
    pppppppCVar6 = (LPSTR ******)
                   FUN_140014ae0(local_98,(ulonglong)pppppppppppCVar8,local_88,pcVar14,
                                 (undefined8 *)local_58,(ulonglong)pppppppppppCVar8);
  }
  else {
    pppppppCVar6 = (LPSTR ******)local_98;
    if (0xf < uStack_80) {
      pppppppCVar6 = local_98[0];
    }
    pppppppppppCVar15 = pppppppppppCVar8;
    if (((pppppppCVar6 < local_58 + (longlong)pppppppppppCVar8) &&
        (local_58 <= (LPSTR)((longlong)pppppppCVar6 + (longlong)local_88))) &&
       (pppppppppppCVar15 = pppppppppppCVar12, local_58 < pppppppCVar6)) {
      pppppppppppCVar15 = (LPSTR **********)((longlong)pppppppCVar6 - (longlong)local_58);
    }
    pCVar13 = local_88 + 1;
    local_88 = local_88 + (longlong)pppppppppppCVar8;
    FUN_1400316b0((undefined8 *)((longlong)pppppppCVar6 + (longlong)pppppppppppCVar8),pppppppCVar6,
                  (ulonglong)pCVar13);
    FUN_1400316b0(pppppppCVar6,(undefined8 *)local_58,(ulonglong)pppppppppppCVar15);
    FUN_1400316b0((undefined8 *)((longlong)pppppppCVar6 + (longlong)pppppppppppCVar15),
                  (undefined8 *)
                  (local_58 + (longlong)((longlong)pppppppppppCVar15 + (longlong)pppppppppppCVar8)),
                  (longlong)pppppppppppCVar8 - (longlong)pppppppppppCVar15);
    pppppppCVar6 = (LPSTR ******)local_98;
  }
  *param_2 = (LPSTR ****)0x0;
  param_2[2] = (LPSTR ****)0x0;
  param_2[3] = (LPSTR ****)0x0;
  ppppppCVar4 = pppppppCVar6[1];
  *param_2 = (LPSTR ****)*pppppppCVar6;
  param_2[1] = (LPSTR ****)ppppppCVar4;
  ppppppCVar4 = pppppppCVar6[3];
  param_2[2] = (LPSTR ****)pppppppCVar6[2];
  param_2[3] = (LPSTR ****)ppppppCVar4;
  pppppppCVar6[2] = (LPSTR *****)0x0;
  pppppppCVar6[3] = (LPSTR *****)0xf;
  *(undefined1 *)pppppppCVar6 = 0;
  if (uStack_80 < 0x10) {
LAB_1400034ae:
    local_88 = (LPSTR)0x0;
    uStack_80 = 0xf;
    local_98[0] = (LPSTR ******)((ulonglong)local_98[0] & 0xffffffffffffff00);
    if (pppppCStack_60 < (LPSTR ****)0x10) {
LAB_140003666:
      FUN_14002f160(local_30 ^ (ulonglong)auStackY_d8);
      return;
    }
    if (((longlong)pppppCStack_60 + 1U < 0x1000) ||
       ((LPSTR)((longlong)local_78 + (-8 - (longlong)local_78[-1])) < (LPSTR)0x20)) {
      FUN_14002f180();
      goto LAB_140003666;
    }
  }
  else {
    if ((uStack_80 + 1 < 0x1000) ||
       ((ulonglong)((longlong)local_98[0] + (-8 - (longlong)local_98[0][-1])) < 0x20)) {
      FUN_14002f180();
      goto LAB_1400034ae;
    }
LAB_140003692:
    FUN_140035d28();
  }
  FUN_140035d28();
LAB_14000369e:
  FUN_140001670();
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400036b0 @ 1400036b0