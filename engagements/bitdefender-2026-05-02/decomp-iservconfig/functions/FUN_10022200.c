void __thiscall
FUN_10022200(void *this,undefined *param_1,char param_2,undefined4 param_3,undefined *param_4,
            undefined *param_5)

{
  longlong lVar1;
  longlong lVar2;
  ulonglong uVar3;
  undefined4 *puVar4;
  short sVar5;
  ushort uVar6;
  int *piVar7;
  int iVar8;
  uint uVar9;
  undefined2 extraout_var;
  uint uVar10;
  code *pcVar11;
  uint uVar12;
  undefined1 *puVar13;
  uint uVar14;
  undefined4 *unaff_ESI;
  undefined *puVar15;
  uint *puVar16;
  int unaff_EDI;
  undefined4 *puVar17;
  double dVar18;
  undefined8 uVar19;
  code *local_40;
  undefined4 *local_3c;
  code *local_38;
  undefined4 *local_34;
  int local_30;
  uint uStack_2c;
  double local_28;
  uint local_20;
  undefined8 local_1c;
  uint uStack_14;
  undefined1 *local_10;
  uint local_c;
  
  lVar1 = CONCAT44(local_1c._4_4_,(uint)local_1c);
  local_c = DAT_10069054 ^ (uint)&local_40;
  local_40 = (code *)param_1;
  local_34 = (undefined4 *)this;
  local_1c = lVar1;
  switch(*param_1) {
  case 1:
                    /* WARNING: Load size is inaccurate */
    puVar17 = (undefined4 *)**this;
    if (*(int *)(*(int *)(param_1 + 8) + 4) == 0) {
      (*(code *)puVar17[1])();
      FUN_1002e315(uStack_14 ^ (uint)&stack0xffffffb8);
      return;
    }
    if (param_2 == '\0') {
      (*(code *)*puVar17)();
      local_40 = (code *)0x0;
      uStack_14 = *(int *)**(undefined4 **)(param_1 + 8);
      if ((*(undefined4 **)(param_1 + 8))[1] != 1) {
        do {
          uVar9 = uStack_14;
                    /* WARNING: Load size is inaccurate */
          (**(code **)**this)();
          FUN_100230f0(this,(undefined4 *)(uVar9 + 0x10));
                    /* WARNING: Load size is inaccurate */
          (**(code **)(**this + 4))();
          FUN_10022200(this,(undefined *)(uVar9 + 0x28),'\0',0,param_4,param_5);
                    /* WARNING: Load size is inaccurate */
          (**(code **)**this)();
          pcVar11 = local_40 + 1;
          local_40 = pcVar11;
          std::
          _Tree_unchecked_const_iterator<class_std::_Tree_val<struct_std::_Tree_simple_types<unsigned_int>_>,struct_std::_Iterator_base0>
          ::operator++((_Tree_unchecked_const_iterator<class_std::_Tree_val<struct_std::_Tree_simple_types<unsigned_int>_>,struct_std::_Iterator_base0>
                        *)&uStack_14);
        } while (pcVar11 < (code *)(*(int *)(unaff_ESI[2] + 4) - 1U));
      }
      uVar9 = uStack_14;
                    /* WARNING: Load size is inaccurate */
      (**(code **)**this)();
      FUN_100230f0(this,(undefined4 *)(uVar9 + 0x10));
                    /* WARNING: Load size is inaccurate */
      (**(code **)(**this + 4))();
      FUN_10022200(this,(undefined *)(uVar9 + 0x28),'\0',0,param_4,param_5);
                    /* WARNING: Load size is inaccurate */
      (**(code **)**this)();
      FUN_1002e315(local_20 ^ (uint)&stack0xffffffac);
      return;
    }
    (*(code *)puVar17[1])();
    if (*(undefined **)((int)this + 0x260) < param_4 + (int)param_5) {
      lVar1 = ZEXT48(*(undefined **)((int)this + 0x260)) * 2;
      FUN_10005410((void *)((int)this + 0x250),
                   -(uint)((int)((ulonglong)lVar1 >> 0x20) != 0) | (uint)lVar1,' ');
    }
    local_1c._4_4_ = *(int *)**(undefined4 **)(param_1 + 8);
    puVar17 = (undefined4 *)this;
    puVar4 = (undefined4 *)0x0;
    if ((*(undefined4 **)(param_1 + 8))[1] != 1) {
      do {
        this = puVar4;
        iVar8 = local_1c._4_4_;
        local_38 = *(code **)(*(int *)*puVar17 + 4);
        (*local_38)();
                    /* WARNING: Load size is inaccurate */
        (**(code **)**this)();
        FUN_100230f0(this,(undefined4 *)(iVar8 + 0x10));
                    /* WARNING: Load size is inaccurate */
        (**(code **)(**this + 4))();
        FUN_10022200(this,(undefined *)(iVar8 + 0x28),'\x01',0,param_4,param_5 + (int)param_4);
                    /* WARNING: Load size is inaccurate */
        (**(code **)(**this + 4))();
        std::
        _Tree_unchecked_const_iterator<class_std::_Tree_val<struct_std::_Tree_simple_types<unsigned_int>_>,struct_std::_Iterator_base0>
        ::operator++((_Tree_unchecked_const_iterator<class_std::_Tree_val<struct_std::_Tree_simple_types<unsigned_int>_>,struct_std::_Iterator_base0>
                      *)((int)&local_1c + 4));
        puVar17 = (undefined4 *)this;
        puVar4 = (undefined4 *)((int)this + 1);
      } while ((undefined4 *)((int)this + 1) <
               (undefined4 *)(*(int *)(*(int *)(unaff_EDI + 8) + 4) + -1));
    }
    iVar8 = local_1c._4_4_;
                    /* WARNING: Load size is inaccurate */
    local_38 = *(code **)(**this + 4);
    (*local_38)();
    (*(code *)**(undefined4 **)*local_3c)();
    FUN_100230f0(local_3c,(undefined4 *)(iVar8 + 0x10));
    (**(code **)(*(int *)*local_3c + 4))();
    FUN_10022200(local_3c,(undefined *)(iVar8 + 0x28),'\x01',0,param_4,param_5 + (int)param_4);
    (*(code *)**(undefined4 **)*local_3c)();
    piVar7 = local_3c + 0x94;
    if (0xf < (uint)local_3c[0x99]) {
      piVar7 = (int *)*piVar7;
    }
    (**(code **)(*(int *)*local_3c + 4))(piVar7);
    (*(code *)**(undefined4 **)*local_3c)(0x7d);
    FUN_1002e315((uint)local_38 ^ (uint)&stack0xffffff94);
    return;
  case 2:
                    /* WARNING: Load size is inaccurate */
    piVar7 = *this;
    if (**(int **)(param_1 + 8) != (*(int **)(param_1 + 8))[1]) {
      if (param_2 == '\0') {
        (**(code **)*piVar7)();
        piVar7 = *(int **)(param_1 + 8);
        puVar15 = (undefined *)*piVar7;
        if (puVar15 != (undefined *)(piVar7[1] + -0x10)) {
          do {
            FUN_10022200(this,puVar15,'\0',0,param_4,param_5);
                    /* WARNING: Load size is inaccurate */
            (**(code **)**this)();
            puVar15 = puVar15 + 0x10;
            piVar7 = (int *)unaff_ESI[2];
          } while (puVar15 != (undefined *)(piVar7[1] + -0x10));
        }
        FUN_10022200(this,(undefined *)(piVar7[1] + -0x10),'\0',0,param_4,param_5);
                    /* WARNING: Load size is inaccurate */
        (**(code **)**this)();
        FUN_1002e315(uStack_14 ^ (uint)&stack0xffffffb8);
        return;
      }
      uVar19 = 0x210060368;
      (*(code *)((undefined4 *)*piVar7)[1])();
      if (*(undefined **)((int)this + 0x260) < param_4 + (int)param_5) {
        lVar1 = ZEXT48(*(undefined **)((int)this + 0x260)) * 2;
        FUN_10005410((void *)((int)this + 0x250),
                     -(uint)((int)((ulonglong)lVar1 >> 0x20) != 0) | (uint)lVar1,' ');
      }
      iVar8 = (int)uVar19;
      puVar15 = (undefined *)**(int **)(param_1 + 8);
      if (puVar15 != (undefined *)((*(int **)(param_1 + 8))[1] + -0x10)) {
        do {
                    /* WARNING: Load size is inaccurate */
          local_40 = *(code **)(**this + 4);
          (*local_40)();
          FUN_10022200(unaff_ESI,puVar15,'\x01',0,param_4,param_5 + (int)param_4);
          (**(code **)(*(int *)*unaff_ESI + 4))();
          iVar8 = (int)uVar19;
          puVar15 = puVar15 + 0x10;
          this = unaff_ESI;
        } while (puVar15 != (undefined *)(*(int *)(*(int *)(unaff_EDI + 8) + 4) + -0x10));
      }
                    /* WARNING: Load size is inaccurate */
      local_38 = *(code **)(**this + 4);
      (*local_38)();
      FUN_10022200(unaff_ESI,(undefined *)(*(int *)(*(int *)(iVar8 + 8) + 4) + -0x10),'\x01',0,
                   param_4,param_4 + (int)param_5);
      (*(code *)**(undefined4 **)*unaff_ESI)();
      (**(code **)(*(int *)*unaff_ESI + 4))();
      (*(code *)**(undefined4 **)*unaff_ESI)();
      FUN_1002e315(uStack_2c ^ (uint)&stack0xffffffa0);
      return;
    }
    goto LAB_10022b4c;
  case 3:
                    /* WARNING: Load size is inaccurate */
    (**(code **)**this)();
    FUN_100230f0(this,*(undefined4 **)(param_1 + 8));
                    /* WARNING: Load size is inaccurate */
    (**(code **)**this)();
    FUN_1002e315(uStack_14 ^ (uint)&stack0xffffffb8);
    return;
  case 4:
                    /* WARNING: Load size is inaccurate */
    iVar8 = **this;
    goto LAB_10022b4e;
  case 5:
    local_40 = *(code **)(param_1 + 8);
    local_3c = *(undefined4 **)(param_1 + 0xc);
    if (local_40 == (code *)0x0 && local_3c == (undefined4 *)0x0) goto LAB_10022734;
    puVar13 = (undefined1 *)((int)this + 8);
    local_28 = (double)CONCAT44(local_28._4_4_,puVar13);
    if (((int)local_3c < 1) && ((int)local_3c < 0)) {
      *puVar13 = 0x2d;
      uVar10 = (int)local_3c >> 0x1f;
      uVar9 = (uint)local_40 ^ uVar10;
      local_40 = (code *)(uVar9 - uVar10);
      local_3c = (undefined4 *)((((uint)local_3c ^ uVar10) - uVar10) - (uint)(uVar9 < uVar10));
      iVar8 = FUN_10023c50((uint)local_40,(uint)local_3c);
      local_38 = (code *)(iVar8 + 1);
    }
    else {
      local_38 = (code *)FUN_10023c50((uint)local_40,(uint)local_3c);
    }
    lVar1 = CONCAT44(local_1c._4_4_,(uint)local_1c);
    puVar13 = puVar13 + (int)local_38;
    local_10 = puVar13;
    if ((local_3c != (undefined4 *)0x0) || ((code *)0x63 < local_40)) {
      do {
        do {
          uVar9 = (uint)local_1c;
          local_20 = (uint)(ZEXT48(local_40) * 0x47ae147a >> 0x20);
          lVar1 = ZEXT48(local_3c) * 0x47ae147a;
          uVar3 = ZEXT48(local_3c) * 0xe147ae15 + (ZEXT48(local_40) * 0xe147ae15 >> 0x20);
          local_1c._0_4_ = (uint)lVar1;
          local_1c._4_4_ = (int)((ulonglong)lVar1 >> 0x20);
          uVar14 = (uint)(uVar3 >> 0x20);
          lVar2 = ZEXT48(local_40) * 0x47ae147a + (uVar3 & 0xffffffff);
          local_30 = (int)lVar2;
          uVar10 = (uint)((ulonglong)lVar2 >> 0x20);
          uVar12 = uVar14 + uVar10;
          pcVar11 = (code *)(uVar9 + uVar12);
          iVar8 = local_1c._4_4_ + (uint)CARRY4(uVar14,uVar10) + (uint)CARRY4(uVar9,uVar12);
          uVar10 = (int)local_3c + (-(uint)(local_40 < pcVar11) - iVar8);
          uVar9 = (uint)((int)local_40 - (int)pcVar11) >> 1 | uVar10 * -0x80000000;
          uVar10 = (uVar10 >> 1) + iVar8 + (uint)CARRY4(uVar9,(uint)pcVar11);
          pcVar11 = (code *)((uint)(pcVar11 + uVar9) >> 6 | uVar10 * 0x4000000);
          local_3c = (undefined4 *)(uVar10 >> 6);
          puVar13 = local_10 + -2;
          local_10[-1] = (&DAT_10060459)[(int)(local_40 + (int)pcVar11 * -100) * 2];
          *puVar13 = (&DAT_10060458)[(int)(local_40 + (int)pcVar11 * -100) * 2];
          local_40 = pcVar11;
          local_10 = puVar13;
        } while (local_3c != (undefined4 *)0x0);
      } while ((code *)0x63 < pcVar11);
      local_3c = (undefined4 *)0x0;
      this = local_34;
    }
    local_10 = puVar13;
    if ((local_3c == (undefined4 *)0x0) && (local_40 < (code *)0xa)) {
      puVar13[-1] = (char)local_40 + '0';
    }
    else {
      puVar13[-1] = (&DAT_10060459)[(int)local_40 * 2];
      puVar13[-2] = (&DAT_10060458)[(int)local_40 * 2];
    }
    break;
  case 6:
    local_40 = *(code **)(param_1 + 8);
    uVar9 = *(uint *)(param_1 + 0xc);
    if (local_40 != (code *)0x0 || uVar9 != 0) {
      local_30 = FUN_10023c50((uint)local_40,uVar9);
      lVar1 = CONCAT44(local_20,(uint)local_1c);
      puVar13 = (undefined1 *)((int)this + local_30 + 8);
      local_10 = puVar13;
      if ((uVar9 != 0) || ((code *)0x63 < local_40)) {
        do {
          do {
            local_1c._4_4_ = (int)(ZEXT48(local_40) * 0x47ae147a >> 0x20);
            lVar1 = (ulonglong)uVar9 * 0x47ae147a;
            uVar3 = (ulonglong)uVar9 * 0xe147ae15 + (ZEXT48(local_40) * 0xe147ae15 >> 0x20);
            uVar14 = (uint)(uVar3 >> 0x20);
            lVar2 = ZEXT48(local_40) * 0x47ae147a + (uVar3 & 0xffffffff);
            uVar10 = (uint)((ulonglong)lVar2 >> 0x20);
            local_28 = (double)CONCAT44((int)((ulonglong)local_28 >> 0x20),(int)lVar2);
            lVar2 = lVar1 + (ulonglong)CONCAT14(CARRY4(uVar14,uVar10),uVar14 + uVar10);
            uVar9 = (uVar9 - (int)((ulonglong)lVar2 >> 0x20)) - (uint)(local_40 < (code *)lVar2);
            lVar2 = lVar2 + CONCAT44(uVar9 >> 1,
                                     (uint)((int)local_40 - (int)(code *)lVar2) >> 1 |
                                     uVar9 * -0x80000000);
            uVar9 = (uint)((ulonglong)lVar2 >> 0x20);
            pcVar11 = (code *)((uint)lVar2 >> 6 | uVar9 * 0x4000000);
            uVar9 = uVar9 >> 6;
            puVar13 = local_10 + -2;
            local_10[-1] = (&DAT_10060459)[(int)(local_40 + (int)pcVar11 * -100) * 2];
            *puVar13 = (&DAT_10060458)[(int)(local_40 + (int)pcVar11 * -100) * 2];
            local_40 = pcVar11;
            local_10 = puVar13;
          } while (uVar9 != 0);
        } while ((code *)0x63 < pcVar11);
        local_3c = (undefined4 *)0x0;
        this = local_34;
      }
      local_20 = (uint)((ulonglong)lVar1 >> 0x20);
      local_1c._0_4_ = (uint)lVar1;
      local_10 = puVar13;
      if (local_40 < (code *)0xa) {
        puVar13[-1] = (char)local_40 + '0';
                    /* WARNING: Load size is inaccurate */
        (**(code **)(**this + 4))();
        FUN_1002e315(uStack_14 ^ (uint)&stack0xffffffb8);
        return;
      }
      puVar13[-1] = (&DAT_10060459)[(int)local_40 * 2];
      puVar13[-2] = (&DAT_10060458)[(int)local_40 * 2];
                    /* WARNING: Load size is inaccurate */
      (**(code **)(**this + 4))();
      FUN_1002e315(uStack_14 ^ (uint)&stack0xffffffb8);
      return;
    }
LAB_10022734:
                    /* WARNING: Load size is inaccurate */
    (**(code **)**this)();
    FUN_1002e315((uint)local_10 ^ (uint)&stack0xffffffbc);
    return;
  case 7:
    local_28 = *(double *)(param_1 + 8);
    local_1c._4_4_ = SUB84(local_28,0);
    uStack_14 = (uint)((ulonglong)local_28 >> 0x20);
    sVar5 = __dclass();
    if (sVar5 < 1) {
      puVar16 = (uint *)((int)this + 8);
      uVar6 = FUN_10039f40(SUB84(local_28,0),(int)((ulonglong)local_28 >> 0x20));
      dVar18 = local_28;
      if (CONCAT22(extraout_var,uVar6) != 0) {
        dVar18 = (double)CONCAT44((uint)((ulonglong)local_28 >> 0x20) ^ _UNK_10061714,
                                  SUB84(local_28,0) ^ _DAT_10061710);
        puVar16 = (uint *)((int)this + 9);
        *(undefined1 *)((int)this + 8) = 0x2d;
      }
      if ((NAN(dVar18) || NAN(_DAT_100616a0)) == (dVar18 == _DAT_100616a0)) {
        local_10 = (undefined1 *)0x0;
        local_38 = (code *)0x0;
        FUN_10023f80(puVar16,(int *)&local_10,(int *)&local_38);
        FUN_1001cd30(puVar16,(uint)local_10,(size_t)local_38);
                    /* WARNING: Load size is inaccurate */
        (**(code **)(**this + 4))();
        FUN_1002e315(uStack_14 ^ (uint)&stack0xffffffb8);
        return;
      }
      *(undefined2 *)puVar16 = 0x2e30;
      *(undefined1 *)((int)puVar16 + 2) = 0x30;
                    /* WARNING: Load size is inaccurate */
      (**(code **)(**this + 4))();
      FUN_1002e315(uStack_14 ^ (uint)&stack0xffffffb8);
      return;
    }
  case 0:
    lVar1 = CONCAT44(local_1c._4_4_,(uint)local_1c);
    break;
  case 8:
    break;
  default:
    goto switchD_1002222f_caseD_9;
  }
                    /* WARNING: Load size is inaccurate */
  piVar7 = *this;
LAB_10022b4c:
  iVar8 = *piVar7;
LAB_10022b4e:
  local_1c = lVar1;
  (**(code **)(iVar8 + 4))();
switchD_1002222f_caseD_9:
  FUN_1002e315(local_c ^ (uint)&local_40);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10022b90 @ 10022b90

/* WARNING: Type propagation algorithm not settling */