
void l2c_rcv_acl_data(int param_1)

{
  byte bVar1;
  byte bVar2;
  bool bVar3;
  int iVar4;
  undefined4 uVar5;
  int iVar6;
  short sVar7;
  char *pcVar8;
  undefined **ppuVar9;
  undefined4 extraout_r1;
  byte *pbVar10;
  byte *pbVar11;
  byte *pbVar12;
  code *pcVar13;
  undefined4 extraout_r1_00;
  undefined4 extraout_r1_01;
  undefined4 extraout_r1_02;
  undefined4 extraout_r1_03;
  ushort uVar14;
  uint uVar15;
  ushort *puVar16;
  uint uVar17;
  ushort uVar18;
  int iVar19;
  uint uVar20;
  byte *pbVar21;
  byte *pbVar22;
  short sVar23;
  uint uVar24;
  uint local_11c;
  int local_10c;
  int local_108;
  int local_104;
  int local_100;
  int local_f8;
  int local_ec;
  int local_e4;
  int local_cc;
  int local_c8;
  int local_c4;
  char *local_a0;
  char *local_98;
  ushort auStack_90 [4];
  short local_88;
  short local_86;
  short local_84;
  ushort local_82;
  undefined4 local_80;
  undefined2 local_7c;
  undefined local_7a;
  ushort local_70;
  undefined local_6e;
  short local_6c;
  undefined local_6a;
  byte local_68;
  byte local_67;
  int local_64;
  int local_60;
  int local_5c;
  int local_58;
  int local_54;
  undefined local_50;
  short local_4e;
  undefined local_4c;
  byte local_4a;
  byte local_49;
  byte local_48;
  short local_46;
  short local_44;
  short local_42;
  undefined local_40;
  byte local_3f;
  undefined local_3e;
  byte local_3c;
  byte local_3b;
  short local_3a;
  int local_38;
  int local_34;
  int local_30;
  short local_2c;
  
  iVar4 = *(ushort *)(param_1 + 4) + 8;
  iVar19 = param_1 + iVar4;
  uVar15 = (uint)*(byte *)(param_1 + iVar4) + (uint)*(byte *)(iVar19 + 1) * 0x100;
  local_11c = uVar15 * 0x40000 >> 0x1e;
  if (local_11c == 1) {
    if (l2cb[0] < 2) goto LAB_0010a452;
    uVar5 = 0x80001;
    pcVar8 = "L2CAP - expected pkt start or complete, got: %d";
  }
  else {
    uVar15 &= 0xfff;
    iVar4 = l2cu_find_lcb_by_handle(uVar15);
    if (iVar4 == 0) {
      sVar7 = *(short *)(param_1 + 6);
      sVar23 = (ushort)*(byte *)(iVar19 + 6) + (ushort)*(byte *)(iVar19 + 7) * 0x100;
      bVar1 = *(byte *)(iVar19 + 8);
      if (((sVar7 == 0) && (sVar23 == 1)) && ((bVar1 & 0xf7) == 2)) {
        if (1 < l2cb[0]) {
          uVar5 = list_length(l2cb._9240_4_);
          LogMsg(0x80001,
                 "L2CAP - holding ACL for unknown handle:%d ls:%d  cid:%d opcode:%d cur count:%d",
                 uVar15,0,1,bVar1,uVar5);
        }
        *(undefined2 *)(param_1 + 6) = 2;
        list_append(l2cb._9240_4_,param_1);
        iVar4 = list_length(l2cb._9240_4_);
        if (iVar4 != 1) {
          return;
        }
        btu_start_timer(0x2a8b1c,4,2);
        return;
      }
      if (l2cb[0] != 0) {
        uVar5 = list_length(l2cb._9240_4_);
        LogMsg(0x80000,"L2CAP - rcvd ACL for unknown handle:%d ls:%d cid:%d opcode:%d cur count:%d",
               uVar15,sVar7,sVar23,bVar1,uVar5);
      }
      goto LAB_0010a452;
    }
    uVar18 = (ushort)*(byte *)(iVar19 + 2) + (ushort)*(byte *)(iVar19 + 3) * 0x100;
    *(short *)(param_1 + 4) = *(short *)(param_1 + 4) + 4;
    if (uVar18 < 4) {
      if (1 < l2cb[0]) {
        LogMsg(0x80001,"L2CAP - got incorrect hci header");
      }
      __android_log_error_write(0x534e4554,"34946955",0xffffffff,0,0);
      goto LAB_0010a452;
    }
    uVar15 = (uint)*(byte *)(iVar19 + 4) + (uint)*(byte *)(iVar19 + 5) * 0x100 & 0xffff;
    local_11c = (uint)*(byte *)(iVar19 + 6) + (uint)*(byte *)(iVar19 + 7) * 0x100 & 0xffff;
    if ((*(char *)(iVar4 + 0x116) == '\x02') && (*(int *)(iVar4 + 4) != 5)) {
      l2cble_notify_le_connection(iVar4 + 0x58);
    }
    if (local_11c < 0x40) {
      iVar6 = 0;
    }
    else {
      iVar6 = l2cu_find_ccb_by_cid(iVar4,local_11c);
      if (iVar6 == 0) {
        if (l2cb[0] < 2) goto LAB_0010a452;
        uVar5 = 0x80001;
        pcVar8 = "L2CAP - unknown CID: 0x%04x";
        goto LAB_0010a4b8;
      }
    }
    uVar18 -= 4;
    *(ushort *)(param_1 + 2) = uVar18;
    ppuVar9 = (undefined **)(*(ushort *)(param_1 + 4) + 4);
    *(short *)(param_1 + 4) = (short)ppuVar9;
    if (uVar15 != uVar18) {
      if (1 < l2cb[0]) {
        LogMsg(0x80001,"L2CAP - bad length in pkt. Exp: %d  Act: %d",uVar15);
      }
      goto LAB_0010a452;
    }
    pbVar21 = (byte *)(iVar19 + 8);
    if (local_11c == 1) {
      counter_add("l2cap.sig.rx.bytes",ppuVar9,uVar15,0);
      counter_add("l2cap.sig.rx.pkts",extraout_r1,1,0);
      if (*(char *)(iVar4 + 0x116) != '\x02') {
        if (uVar15 < 0x2a1) {
          local_11c = 0;
        }
        else if (l2cb[0] != 0) {
          LogMsg(0x80000,"L2CAP SIG MTU Pkt Len Exceeded (672) -> pkt_len: %d",uVar15);
        }
        memset(&local_70,0,0x48);
        local_a0 = "L2CAP - cfg rsp - bad ID. Exp: %d Got: %d";
        local_98 = "L2CAP - no CCB for conn rsp, LCID: %d RCID: %d";
        pbVar22 = pbVar21;
LAB_0010a580:
        if (pbVar21 + uVar15 + -4 < pbVar22) goto LAB_0010a452;
        uVar17 = (uint)pbVar22[2] + (uint)pbVar22[3] * 0x100 & 0xffff;
        pbVar10 = pbVar22 + uVar17 + 4;
        bVar1 = *pbVar22;
        bVar2 = pbVar22[1];
        uVar18 = (ushort)bVar2;
        if (pbVar21 + uVar15 < pbVar10) {
          if (1 < l2cb[0]) {
            LogMsg(0x80001,"Command len bad  pkt_len: %d  cmd_len: %d  code: %d",uVar15,uVar17,bVar1
                  );
          }
          goto LAB_0010a452;
        }
        if (4 < l2cb[0]) {
          LogMsg(0x80004,"cmd_code: %d, id:%d, cmd_len:%d",bVar1,uVar18,uVar17);
        }
        if (local_11c != 0) goto code_r0x0010a5ea;
        switch(bVar1) {
        case 1:
          sVar7 = (ushort)pbVar22[4] + (ushort)pbVar22[5] * 0x100;
          if (sVar7 == 1) {
            pbVar11 = pbVar22 + 6;
            pbVar12 = pbVar22 + 7;
            pbVar22 = pbVar10;
            if (1 < l2cb[0]) {
              uVar14 = *(ushort *)(iVar4 + 0x28);
              pcVar8 = "L2CAP - MTU rej Handle: %d MTU: %d";
              uVar18 = (ushort)*pbVar11 + (ushort)*pbVar12 * 0x100;
              goto LAB_0010a864;
            }
          }
          else if (sVar7 == 2) {
            sVar23 = (ushort)pbVar22[6] + (ushort)pbVar22[7] * 0x100;
            sVar7 = (ushort)pbVar22[8] + (ushort)pbVar22[9] * 0x100;
            if (1 < l2cb[0]) {
              LogMsg(0x80001,"L2CAP - rej with CID invalid, LCID: 0x%04x RCID: 0x%04x",sVar7,sVar23)
              ;
            }
            iVar19 = l2cu_find_ccb_by_cid(iVar4,sVar7);
            pbVar22 = pbVar10;
            if ((iVar19 != 0) && (*(short *)(iVar19 + 0x16) == sVar23)) {
              uVar5 = 3;
              puVar16 = (ushort *)0x0;
              break;
            }
          }
          else {
            pbVar22 = pbVar10;
            if ((sVar7 == 0) && (*(char *)(iVar4 + 0x73) != '\0')) {
              btu_stop_timer(iVar4 + 0x38);
              *(undefined *)(iVar4 + 0x73) = 0;
              local_80 = *(undefined4 *)(iVar4 + 0x58);
              iVar19 = *(int *)(iVar4 + 0x2c);
              local_7c = *(undefined2 *)(iVar4 + 0x5c);
              local_7a = 0;
              for (; iVar19 != 0; iVar19 = *(int *)(iVar19 + 8)) {
                l2c_csm_execute(iVar19,0x13,&local_80);
              }
            }
          }
          goto LAB_0010a580;
        case 2:
          local_88 = (ushort)pbVar22[4] + (ushort)pbVar22[5] * 0x100;
          sVar7 = (ushort)pbVar22[6] + (ushort)pbVar22[7] * 0x100;
          iVar6 = l2cu_find_rcb_by_psm();
          if (iVar6 == 0) {
            if (1 < l2cb[0]) {
              pcVar8 = "L2CAP - rcvd conn req for unknown PSM: %d";
LAB_0010a7a2:
              LogMsg(0x80001,pcVar8,local_88);
            }
LAB_0010a7aa:
            uVar5 = 2;
          }
          else {
            if (*(int *)(iVar6 + 8) == 0) {
              if (1 < l2cb[0]) {
                pcVar8 = "L2CAP - rcvd conn req for outgoing-only connection PSM: %d";
                goto LAB_0010a7a2;
              }
              goto LAB_0010a7aa;
            }
            iVar19 = l2cu_allocate_ccb(iVar4,0);
            if (iVar19 != 0) {
              *(byte *)(iVar19 + 0x3f) = bVar2;
              uVar5 = 10;
              *(int *)(iVar19 + 0x38) = iVar6;
              *(short *)(iVar19 + 0x16) = sVar7;
              goto LAB_0010b058;
            }
            if (l2cb[0] != 0) {
              LogMsg(0x80000,"L2CAP - unable to allocate CCB");
            }
            uVar5 = 4;
          }
          l2cu_reject_connection(iVar4,sVar7,uVar18,uVar5);
          pbVar22 = pbVar10;
          goto LAB_0010a580;
        case 3:
          local_82 = (ushort)pbVar22[4] + (ushort)pbVar22[5] * 0x100;
          uVar14 = (ushort)pbVar22[6] + (ushort)pbVar22[7] * 0x100;
          local_86 = (ushort)pbVar22[8] + (ushort)pbVar22[9] * 0x100;
          local_84 = (ushort)pbVar22[10] + (ushort)pbVar22[0xb] * 0x100;
          iVar19 = l2cu_find_ccb_by_cid(iVar4,uVar14);
          if (iVar19 == 0) {
            pcVar8 = local_98;
            pbVar22 = pbVar10;
            uVar18 = local_82;
            if (l2cb[0] < 2) goto LAB_0010a580;
          }
          else {
            uVar14 = (ushort)*(byte *)(iVar19 + 0x3e);
            if (uVar14 == uVar18) {
              puVar16 = auStack_90;
              if (local_86 == 0) {
                uVar5 = 0xb;
              }
              else if (local_86 == 1) {
                uVar5 = 0xc;
              }
              else {
                uVar5 = 0xd;
              }
              break;
            }
            pbVar22 = pbVar10;
            if (l2cb[0] < 2) goto LAB_0010a580;
            pcVar8 = "L2CAP - con rsp - bad ID. Exp: %d Got: %d";
          }
LAB_0010a864:
          LogMsg(0x80001,pcVar8,uVar14,uVar18);
          pbVar22 = pbVar10;
          goto LAB_0010a580;
        case 4:
          local_2c = (ushort)pbVar22[6] + (ushort)pbVar22[7] * 0x100;
          local_c8 = local_60;
          local_cc = local_5c;
          local_6a = 0;
          local_c4 = local_64;
          local_50 = 0;
          uVar20 = 0;
          bVar3 = false;
          local_6e = 0;
          local_104 = local_38;
          local_108 = local_34;
          local_10c = local_30;
          local_40 = 0;
          local_4c = 0;
          pbVar11 = pbVar22 + 8;
LAB_0010a940:
          while (pbVar11 < pbVar10) {
            bVar1 = *pbVar11;
            uVar24 = (uint)pbVar11[1];
            switch(bVar1 & 0x7f) {
            case 1:
              local_6c = (ushort)pbVar11[2] + (ushort)pbVar11[3] * 0x100;
              local_6e = 1;
              pbVar11 = pbVar11 + 4;
              break;
            case 2:
              local_4e = (ushort)pbVar11[2] + (ushort)pbVar11[3] * 0x100;
              local_50 = 1;
              pbVar11 = pbVar11 + 4;
              break;
            case 3:
              local_68 = pbVar11[2];
              local_67 = pbVar11[3];
              local_c4 = (uint)pbVar11[6] * 0x10000 + (uint)pbVar11[5] * 0x100 + (uint)pbVar11[4] +
                         (uint)pbVar11[7] * 0x1000000;
              local_c8 = (uint)pbVar11[10] * 0x10000 + (uint)pbVar11[9] * 0x100 + (uint)pbVar11[8] +
                         (uint)pbVar11[0xb] * 0x1000000;
              local_cc = (uint)pbVar11[0xe] * 0x10000 + (uint)pbVar11[0xd] * 0x100 +
                         (uint)pbVar11[0xc] + (uint)pbVar11[0xf] * 0x1000000;
              local_58 = (uint)pbVar11[0x12] * 0x10000 + (uint)pbVar11[0x11] * 0x100 +
                         (uint)pbVar11[0x10] + (uint)pbVar11[0x13] * 0x1000000;
              local_54 = (uint)pbVar11[0x16] * 0x10000 + (uint)pbVar11[0x15] * 0x100 +
                         (uint)pbVar11[0x14] + (uint)pbVar11[0x17] * 0x1000000;
              local_6a = 1;
              pbVar11 = pbVar11 + 0x18;
              break;
            case 4:
              local_4a = pbVar11[2];
              local_49 = pbVar11[3];
              local_48 = pbVar11[4];
              local_46 = (ushort)pbVar11[5] + (ushort)pbVar11[6] * 0x100;
              local_44 = (ushort)pbVar11[7] + (ushort)pbVar11[8] * 0x100;
              local_42 = (ushort)pbVar11[9] + (ushort)pbVar11[10] * 0x100;
              local_4c = 1;
              pbVar11 = pbVar11 + 0xb;
              break;
            case 5:
              local_3f = pbVar11[2];
              local_40 = 1;
              pbVar11 = pbVar11 + 3;
              break;
            case 6:
              local_3c = pbVar11[2];
              local_3b = pbVar11[3];
              local_3a = (ushort)pbVar11[4] + (ushort)pbVar11[5] * 0x100;
              local_104 = (uint)pbVar11[8] * 0x10000 + (uint)pbVar11[7] * 0x100 + (uint)pbVar11[6] +
                          (uint)pbVar11[9] * 0x1000000;
              local_108 = (uint)pbVar11[0xc] * 0x10000 + (uint)pbVar11[0xb] * 0x100 +
                          (uint)pbVar11[10] + (uint)pbVar11[0xd] * 0x1000000;
              local_10c = (uint)pbVar11[0x10] * 0x10000 + (uint)pbVar11[0xf] * 0x100 +
                          (uint)pbVar11[0xe] + (uint)pbVar11[0x11] * 0x1000000;
              local_3e = 1;
              pbVar11 = pbVar11 + 0x12;
              break;
            default:
              pbVar12 = pbVar10;
              if (uVar24 + 1 < uVar17) goto code_r0x0010ab26;
              goto LAB_0010ab42;
            }
          }
          local_64 = local_c4;
          local_60 = local_c8;
          local_5c = local_cc;
          local_34 = local_108;
          local_30 = local_10c;
          local_38 = local_104;
          iVar19 = l2cu_find_ccb_by_cid(iVar4,(ushort)pbVar22[4] + (ushort)pbVar22[5] * 0x100);
          if (iVar19 == 0) {
            l2cu_send_peer_cmd_reject(iVar4,2,uVar18,0,0);
            pbVar22 = pbVar10;
            goto LAB_0010a580;
          }
          *(byte *)(iVar19 + 0x3f) = bVar2;
          if (bVar3) {
            l2cu_send_peer_config_rej(iVar19,pbVar22 + 8,uVar17 - 4 & 0xffff,uVar20);
            pbVar22 = pbVar10;
            goto LAB_0010a580;
          }
          uVar5 = 0xe;
          puVar16 = &local_70;
          break;
        case 5:
          sVar7 = (ushort)pbVar22[4] + (ushort)pbVar22[5] * 0x100;
          local_2c = (ushort)pbVar22[6] + (ushort)pbVar22[7] * 0x100;
          local_70 = (ushort)pbVar22[8] + (ushort)pbVar22[9] * 0x100;
          local_6a = 0;
          local_50 = 0;
          local_100 = local_64;
          local_c4 = local_60;
          local_4c = 0;
          local_6e = 0;
          local_40 = 0;
          local_e4 = local_38;
          local_f8 = local_34;
          local_ec = local_30;
          pbVar22 = pbVar22 + 10;
          while (pbVar11 = pbVar22, pbVar11 < pbVar10) {
            pbVar22 = pbVar11 + 2;
            switch(*pbVar11 & 0x7f) {
            case 1:
              local_6c = (ushort)pbVar11[2] + (ushort)pbVar11[3] * 0x100;
              local_6e = 1;
              pbVar22 = pbVar11 + 4;
              break;
            case 2:
              local_4e = (ushort)pbVar11[2] + (ushort)pbVar11[3] * 0x100;
              local_50 = 1;
              pbVar22 = pbVar11 + 4;
              break;
            case 3:
              local_68 = pbVar11[2];
              local_67 = pbVar11[3];
              local_100 = (uint)pbVar11[6] * 0x10000 + (uint)pbVar11[5] * 0x100 + (uint)pbVar11[4] +
                          (uint)pbVar11[7] * 0x1000000;
              local_c4 = (uint)pbVar11[10] * 0x10000 + (uint)pbVar11[9] * 0x100 + (uint)pbVar11[8] +
                         (uint)pbVar11[0xb] * 0x1000000;
              local_5c = (uint)pbVar11[0xe] * 0x10000 + (uint)pbVar11[0xd] * 0x100 +
                         (uint)pbVar11[0xc] + (uint)pbVar11[0xf] * 0x1000000;
              local_58 = (uint)pbVar11[0x12] * 0x10000 + (uint)pbVar11[0x11] * 0x100 +
                         (uint)pbVar11[0x10] + (uint)pbVar11[0x13] * 0x1000000;
              local_6a = 1;
              local_54 = (uint)pbVar11[0x16] * 0x10000 + (uint)pbVar11[0x15] * 0x100 +
                         (uint)pbVar11[0x14] + (uint)pbVar11[0x17] * 0x1000000;
              pbVar22 = pbVar11 + 0x18;
              break;
            case 4:
              local_4a = pbVar11[2];
              local_49 = pbVar11[3];
              local_46 = (ushort)pbVar11[5] + (ushort)pbVar11[6] * 0x100;
              local_48 = pbVar11[4];
              local_44 = (ushort)pbVar11[7] + (ushort)pbVar11[8] * 0x100;
              local_42 = (ushort)pbVar11[9] + (ushort)pbVar11[10] * 0x100;
              local_4c = 1;
              pbVar22 = pbVar11 + 0xb;
              break;
            case 5:
              local_3f = pbVar11[2];
              local_40 = 1;
              pbVar22 = pbVar11 + 3;
              break;
            case 6:
              local_3c = pbVar11[2];
              local_3b = pbVar11[3];
              local_3a = (ushort)pbVar11[4] + (ushort)pbVar11[5] * 0x100;
              local_e4 = (uint)pbVar11[8] * 0x10000 + (uint)pbVar11[7] * 0x100 + (uint)pbVar11[6] +
                         (uint)pbVar11[9] * 0x1000000;
              local_f8 = (uint)pbVar11[0xc] * 0x10000 + (uint)pbVar11[0xb] * 0x100 +
                         (uint)pbVar11[10] + (uint)pbVar11[0xd] * 0x1000000;
              local_ec = (uint)pbVar11[0x10] * 0x10000 + (uint)pbVar11[0xf] * 0x100 +
                         (uint)pbVar11[0xe] + (uint)pbVar11[0x11] * 0x1000000;
              local_3e = 1;
              pbVar22 = pbVar11 + 0x12;
            }
          }
          local_64 = local_100;
          local_60 = local_c4;
          local_38 = local_e4;
          local_34 = local_f8;
          local_30 = local_ec;
          iVar19 = l2cu_find_ccb_by_cid(iVar4,sVar7);
          if (iVar19 == 0) {
            pbVar22 = pbVar10;
            if (1 < l2cb[0]) {
              LogMsg(0x80001,"L2CAP - rcvd cfg rsp for unknown CID: 0x%04x",sVar7);
            }
            goto LAB_0010a580;
          }
          uVar14 = (ushort)*(byte *)(iVar19 + 0x3e);
          if (uVar14 != uVar18) {
            pcVar8 = local_a0;
            pbVar22 = pbVar10;
            if (1 < l2cb[0]) goto LAB_0010a864;
            goto LAB_0010a580;
          }
          puVar16 = &local_70;
          if ((local_70 & 0xfffb) == 0) {
            uVar5 = 0xf;
          }
          else {
            uVar5 = 0x10;
          }
          break;
        case 6:
          sVar23 = (ushort)pbVar22[4] + (ushort)pbVar22[5] * 0x100;
          sVar7 = (ushort)pbVar22[6] + (ushort)pbVar22[7] * 0x100;
          iVar19 = l2cu_find_ccb_by_cid(iVar4,sVar23);
          if (iVar19 == 0) {
            l2cu_send_peer_disc_rsp(iVar4,uVar18,sVar23,sVar7);
            pbVar22 = pbVar10;
          }
          else {
            pbVar22 = pbVar10;
            if (*(short *)(iVar19 + 0x16) == sVar7) {
              *(byte *)(iVar19 + 0x3f) = bVar2;
              uVar5 = 0x11;
              goto LAB_0010b058;
            }
          }
          goto LAB_0010a580;
        case 7:
          bVar1 = pbVar22[5];
          bVar2 = pbVar22[4];
          iVar19 = l2cu_find_ccb_by_cid(iVar4,(ushort)pbVar22[6] + (ushort)pbVar22[7] * 0x100);
          pbVar22 = pbVar10;
          if (((iVar19 == 0) ||
              (*(short *)(iVar19 + 0x16) != (ushort)((ushort)bVar2 + (ushort)bVar1 * 0x100))) ||
             (*(byte *)(iVar19 + 0x3e) != uVar18)) goto LAB_0010a580;
          uVar5 = 0x12;
LAB_0010b058:
          puVar16 = auStack_90;
          break;
        case 8:
          l2cu_send_peer_echo_rsp(iVar4,uVar18,0,0);
          pbVar22 = pbVar10;
          goto LAB_0010a580;
        case 9:
          pcVar13 = *(code **)(iVar4 + 100);
          pbVar22 = pbVar10;
          if (pcVar13 != (code *)0x0) {
            *(undefined4 *)(iVar4 + 100) = 0;
            (*pcVar13)();
          }
          goto LAB_0010a580;
        case 10:
          l2cu_send_peer_info_rsp(iVar4,uVar18,(ushort)pbVar22[4] + (ushort)pbVar22[5] * 0x100);
          pbVar22 = pbVar10;
          goto LAB_0010a580;
        case 0xb:
          uVar20 = (uint)pbVar22[4] + (uint)pbVar22[5] * 0x100;
          uVar17 = uVar20 & 0xffff;
          sVar7 = (ushort)pbVar22[6] + (ushort)pbVar22[7] * 0x100;
          *(byte *)(iVar4 + 0x74) = (byte)(1 << (uVar20 & 0xff)) | *(byte *)(iVar4 + 0x74);
          if (uVar17 == 2) {
            if (sVar7 == 0) {
              bVar1 = pbVar22[8];
              *(uint *)(iVar4 + 0x78) =
                   (uint)pbVar22[10] * 0x10000 + (uint)pbVar22[9] * 0x100 + (uint)bVar1 +
                   (uint)pbVar22[0xb] * 0x1000000;
              if ((int)((uint)bVar1 * 0x1000000) < 0) {
                l2cu_send_peer_info_req(iVar4,3);
                pbVar22 = pbVar10;
                goto LAB_0010a580;
              }
LAB_0010b118:
              l2cu_process_fixed_chnl_resp(iVar4);
            }
          }
          else if (uVar17 == 3) {
            if (sVar7 == 0) {
              *(undefined4 *)(iVar4 + 0x80) = *(undefined4 *)(pbVar22 + 8);
              *(undefined4 *)(iVar4 + 0x84) = *(undefined4 *)(pbVar22 + 0xc);
            }
            goto LAB_0010b118;
          }
          pbVar22 = pbVar10;
          if (*(char *)(iVar4 + 0x73) != '\0') {
            btu_stop_timer(iVar4 + 0x38);
            iVar19 = *(int *)(iVar4 + 0x2c);
            *(undefined *)(iVar4 + 0x73) = 0;
            local_80 = *(undefined4 *)(iVar4 + 0x58);
            local_7a = 0;
            local_7c = *(undefined2 *)(iVar4 + 0x5c);
            for (; iVar19 != 0; iVar19 = *(int *)(iVar19 + 8)) {
              l2c_csm_execute(iVar19,0x13,&local_80);
            }
          }
          goto LAB_0010a580;
        default:
          if (1 < l2cb[0]) {
            LogMsg(0x80001,"L2CAP - bad cmd code: %d",bVar1);
          }
          l2cu_send_peer_cmd_reject(iVar4,0,uVar18,0,0);
          goto LAB_0010a452;
        }
        l2c_csm_execute(iVar19,uVar5,puVar16);
        pbVar22 = pbVar10;
        goto LAB_0010a580;
      }
      goto LAB_0010a452;
    }
    if (local_11c != 2) {
      if (local_11c == 5) {
        counter_add("l2cap.ble.rx.bytes",ppuVar9,uVar15,0);
        counter_add("l2cap.ble.rx.pkts",extraout_r1_01,1,0);
        l2cble_process_sig_cmd(iVar4,pbVar21,uVar15);
        goto LAB_0010a452;
      }
      if ((local_11c - 4 & 0xffff) < 0x20) {
        ppuVar9 = &__DT_PLTGOT;
        iVar19 = (local_11c - 4) * 0x1c;
        if (*(int *)(l2cb + iVar19 + 0x244c) != 0) {
          counter_add("l2cap.fix.rx.bytes",&__DT_PLTGOT,uVar15,0);
          counter_add("l2cap.fix.rx.pkts",extraout_r1_02,1,0);
          if ((*(int *)(iVar4 + 4) == 5) ||
             (iVar6 = l2cu_initialize_fixed_ccb(iVar4,local_11c,iVar19 + 0x2a8b54), iVar6 == 0))
          goto LAB_0010a452;
          iVar6 = *(int *)(iVar4 + local_11c * 4 + 0x84);
          if (*(char *)(iVar6 + 0xb6) == '\0') {
            (**(code **)(l2cb + iVar19 + 0x244c))(local_11c,iVar4 + 0x58,param_1);
            return;
          }
          goto LAB_0010b2c2;
        }
      }
      counter_add("l2cap.dyn.rx.bytes",ppuVar9,uVar15,0);
      counter_add("l2cap.dyn.rx.pkts",extraout_r1_03,1,0);
      if (iVar6 != 0) {
        if (*(char *)(iVar6 + 0xb6) == '\0') {
          l2c_csm_execute(iVar6,0x14,param_1);
          return;
        }
        if (*(int *)(iVar6 + 4) - 5U < 2) {
LAB_0010b2c2:
          l2c_fcr_proc_pdu(iVar6,param_1);
          return;
        }
      }
      goto LAB_0010a452;
    }
    counter_add("l2cap.ch2.rx.bytes",ppuVar9,uVar15,0);
    counter_add("l2cap.ch2.rx.pkts",extraout_r1_00,1,0);
    if (l2cb[0] < 5) goto LAB_0010a452;
    uVar5 = 0x80004;
    local_11c = (uint)*(byte *)(iVar19 + 8) + (uint)*(byte *)(iVar19 + 9) * 0x100 & 0xffff;
    pcVar8 = "GOT CONNECTIONLESS DATA PSM:%d";
  }
LAB_0010a4b8:
  LogMsg(uVar5,pcVar8,local_11c);
LAB_0010a452:
  GKI_freebuf(param_1);
  return;
code_r0x0010a5ea:
  iVar19 = l2c_is_cmd_rejected(bVar1,uVar18,iVar4);
  pbVar22 = pbVar10;
  if (iVar19 != 0) goto LAB_0010a452;
  goto LAB_0010a580;
code_r0x0010ab26:
  pbVar11 = pbVar11 + uVar24 + 2;
  if (-1 < (int)((uint)bVar1 << 0x18)) {
    uVar20 = uVar24 + (uVar20 + 2 & 0xffff) & 0xffff;
    pbVar12 = pbVar11;
LAB_0010ab42:
    bVar3 = true;
    pbVar11 = pbVar12;
  }
  goto LAB_0010a940;
}

