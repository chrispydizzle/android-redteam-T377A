
void l2c_csm_execute(int param_1,uint param_2,short *param_3)

{
  byte bVar1;
  byte bVar2;
  short sVar3;
  undefined2 uVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  code *pcVar8;
  undefined4 uVar9;
  code *pcVar10;
  bool bVar11;
  undefined auStack_34 [16];
  
  switch(*(undefined4 *)(param_1 + 4)) {
  case 0:
    iVar7 = *(int *)(param_1 + 0x38);
    uVar4 = *(undefined2 *)(param_1 + 0x14);
    if (iVar7 == 0) {
      if (l2cb[0] == 0) {
        return;
      }
      LogMsg(0x80000,"L2CAP - LCID: 0x%04x  st: CLOSED  evt: 0x%04x p_rcb == NULL",uVar4,param_2);
      return;
    }
    pcVar10 = *(code **)(iVar7 + 0x1c);
    pcVar8 = *(code **)(iVar7 + 0xc);
    if (3 < l2cb[0]) {
      LogMsg(0x80003,"L2CAP - st: CLOSED evt: %d",param_2);
    }
    switch(param_2) {
    case 0:
      *(undefined4 *)(param_1 + 4) = 1;
      btm_sec_l2cap_access_req
                (*(int *)(param_1 + 0x10) + 0x58,*(undefined2 *)(*(int *)(param_1 + 0x38) + 2),
                 *(undefined2 *)(*(int *)(param_1 + 0x10) + 0x28),1,l2c_link_sec_comp + 1,param_1);
      break;
    case 1:
      if ((*(char *)(param_3 + 3) != '\v') ||
         (iVar7 = btm_acl_notif_conn_collision(*(int *)(param_1 + 0x10) + 0x58), iVar7 == 0)) {
        if (2 < l2cb[0]) {
          LogMsg(0x80002,"L2CAP - Calling ConnectCfm_Cb(), CID: 0x%04x  Status: %d",
                 *(undefined2 *)(param_1 + 0x14),*(char *)(param_3 + 3));
        }
        l2cu_release_ccb(param_1);
        (*pcVar8)(uVar4,*(char *)(param_3 + 3));
      }
      break;
    case 3:
      if (2 < l2cb[0]) {
        LogMsg(0x80002,"L2CAP - Calling Disconnect_Ind_Cb(), CID: 0x%04x  No Conf Needed",
               *(undefined2 *)(param_1 + 0x14));
      }
      l2cu_release_ccb(param_1);
      (*pcVar10)(uVar4,0);
      break;
    case 7:
      *(undefined4 *)(param_1 + 4) = 3;
      if (*(char *)(*(int *)(param_1 + 0x10) + 0x73) == '\0') {
        iVar7 = l2c_fcr_chk_chan_modes(param_1);
        if (iVar7 == 0) {
          l2cu_release_ccb(param_1);
          (**(code **)(*(int *)(param_1 + 0x38) + 0xc))(uVar4,0xff);
        }
        else {
          l2cu_send_peer_connect_req(param_1);
          btu_start_timer(param_1 + 0x18,3,0x3c);
        }
      }
      break;
    case 8:
      if (2 < l2cb[0]) {
        LogMsg(0x80002,"L2CAP - Calling ConnectCfm_Cb(), CID: 0x%04x  Status: %d",
               *(undefined2 *)(param_1 + 0x14),0xeeee);
      }
      l2cu_release_ccb(param_1);
      (*pcVar8)(uVar4,3);
      break;
    case 10:
      btu_stop_timer(*(int *)(param_1 + 0x10) + 8);
      memset(auStack_34,0,10);
      BTM_SetPowerMode(0x80,*(int *)(param_1 + 0x10) + 0x58,auStack_34);
      *(undefined4 *)(param_1 + 4) = 2;
      iVar7 = btm_sec_l2cap_access_req
                        (*(int *)(param_1 + 0x10) + 0x58,
                         *(undefined2 *)(*(int *)(param_1 + 0x38) + 2),
                         *(undefined2 *)(*(int *)(param_1 + 0x10) + 0x28),0,l2c_link_sec_comp + 1,
                         param_1);
      if (iVar7 != 1) {
        return;
      }
LAB_0010ff18:
      l2cu_send_peer_connect_rsp(param_1,1,0);
      break;
    case 0x14:
    case 0x1e:
      GKI_freebuf(param_3);
      break;
    case 0x15:
      memset(auStack_34,0,10);
      BTM_SetPowerMode(0x80,*(int *)(param_1 + 0x10) + 0x58,auStack_34);
      iVar7 = btm_sec_l2cap_access_req
                        (*(int *)(param_1 + 0x10) + 0x58,
                         *(undefined2 *)(*(int *)(param_1 + 0x38) + 2),
                         *(undefined2 *)(*(int *)(param_1 + 0x10) + 0x28),1,l2c_link_sec_comp + 1,
                         param_1);
      if (iVar7 == 1) {
        *(undefined4 *)(param_1 + 4) = 1;
      }
      break;
    case 0x1b:
      l2cu_release_ccb(param_1);
      break;
    case 0x20:
      if (2 < l2cb[0]) {
        LogMsg(0x80002,"L2CAP - Calling ConnectCfm_Cb(), CID: 0x%04x  Status: %d",
               *(undefined2 *)(param_1 + 0x14),0xeeee);
      }
      l2cu_release_ccb(param_1);
      (*pcVar8)(uVar4,0xeeee);
    }
    break;
  case 1:
    uVar4 = *(undefined2 *)(param_1 + 0x14);
    pcVar10 = *(code **)(*(int *)(param_1 + 0x38) + 0x1c);
    pcVar8 = *(code **)(*(int *)(param_1 + 0x38) + 0xc);
    if (3 < l2cb[0]) {
      LogMsg(0x80003,"L2CAP - st: ORIG_W4_SEC_COMP evt: %d",param_2);
    }
    if (param_2 == 8) {
      if (2 < l2cb[0]) {
        LogMsg(0x80002,"L2CAP - Calling ConnectCfm_Cb(), CID: 0x%04x  Status: %d",
               *(undefined2 *)(param_1 + 0x14),5);
      }
      iVar7 = *(int *)(param_1 + 0x10);
      if (param_1 == *(int *)(iVar7 + 0x2c)) {
        iVar5 = *(int *)(iVar7 + 0x30);
        bVar11 = param_1 == iVar5;
        if (bVar11) {
          iVar5 = 0;
        }
        if (bVar11) {
          *(short *)(iVar7 + 0x68) = (short)iVar5;
        }
      }
      l2cu_release_ccb(param_1);
      (*pcVar8)(uVar4,5);
      return;
    }
    if (8 < param_2) {
      if (param_2 == 0x1b) {
        btm_sec_abort_access_req(*(int *)(param_1 + 0x10) + 0x58);
        l2cu_release_ccb(param_1);
        return;
      }
      if (param_2 < 0x1c) {
        if (param_2 != 0x14) {
          return;
        }
      }
      else if (param_2 != 0x1e) {
        if (param_2 != 0x21) {
          return;
        }
        goto LAB_0010ffd6;
      }
      GKI_freebuf(param_3);
      return;
    }
    if (param_2 == 3) {
      if (2 < l2cb[0]) {
        LogMsg(0x80002,"L2CAP - Calling Disconnect_Ind_Cb(), CID: 0x%04x  No Conf Needed",
               *(undefined2 *)(param_1 + 0x14));
      }
      l2cu_release_ccb(param_1);
      (*pcVar10)(uVar4,0);
      return;
    }
    if (param_2 != 7) {
      if (param_2 != 0) {
        return;
      }
LAB_0010ffd6:
      btm_sec_l2cap_access_req
                (*(int *)(param_1 + 0x10) + 0x58,*(undefined2 *)(*(int *)(param_1 + 0x38) + 2),
                 *(undefined2 *)(*(int *)(param_1 + 0x10) + 0x28),1,l2c_link_sec_comp + 1,param_1);
      return;
    }
    *(undefined4 *)(param_1 + 4) = 3;
    if (*(char *)(*(int *)(param_1 + 0x10) + 0x73) != '\0') {
      return;
    }
    iVar7 = l2c_fcr_chk_chan_modes(param_1);
    if (iVar7 == 0) {
      l2cu_release_ccb(param_1);
      (*pcVar8)(uVar4,0xff);
      return;
    }
    goto LAB_0011001e;
  case 2:
    if (3 < l2cb[0]) {
      LogMsg(0x80003,"L2CAP - st: TERM_W4_SEC_COMP evt: %d",param_2);
    }
    if (param_2 != 0x14) {
      if (param_2 < 0x15) {
        if (param_2 != 7) {
          if (param_2 < 8) {
            if (param_2 != 3) {
              return;
            }
            btm_sec_abort_access_req(*(int *)(param_1 + 0x10) + 0x58);
            l2cu_release_ccb(param_1);
            return;
          }
          if (param_2 == 8) {
            if (*(char *)(param_3 + 3) == '\x0f') {
              btu_start_timer(param_1 + 0x18,3,2);
              return;
            }
            l2cu_send_peer_connect_rsp(param_1,3,0);
            l2cu_release_ccb(param_1);
            return;
          }
          if (param_2 != 0x11) {
            return;
          }
          l2cu_send_peer_disc_rsp
                    (*(undefined4 *)(param_1 + 0x10),*(undefined *)(param_1 + 0x3f),
                     *(undefined2 *)(param_1 + 0x14),*(undefined2 *)(param_1 + 0x16));
          btm_sec_abort_access_req(*(int *)(param_1 + 0x10) + 0x58);
          l2cu_release_ccb(param_1);
          return;
        }
        *(undefined4 *)(param_1 + 4) = 4;
        if (*(char *)(*(int *)(param_1 + 0x10) + 0x73) == '\0') {
          btu_start_timer(param_1 + 0x18,3,0x3c);
          if (2 < l2cb[0]) {
            LogMsg(0x80002,"L2CAP - Calling Connect_Ind_Cb(), CID: 0x%04x",
                   *(undefined2 *)(param_1 + 0x14));
          }
          (**(code **)(*(int *)(param_1 + 0x38) + 8))
                    (*(int *)(param_1 + 0x10) + 0x58,*(undefined2 *)(param_1 + 0x14),
                     *(undefined2 *)(*(int *)(param_1 + 0x38) + 2),*(undefined *)(param_1 + 0x3f));
          return;
        }
        iVar7 = iop_exception_skip_sdp_info(*(int *)(param_1 + 0x10) + 0x58);
        if (iVar7 != 0) {
          if (*(char *)(*(int *)(param_1 + 0x10) + 0x73) == '\0') {
            return;
          }
          if (1 < l2cb[0]) {
            LogMsg(0x80001,"Don\'t wait for info response and send Connect_Ind to upper layer");
          }
          btu_start_timer(param_1 + 0x18,3,0x3c);
          if (l2cb[0] != 0) {
            LogMsg(0x80000,"L2CAP - Calling Connect_Ind_Cb(), CID: 0x%04x",
                   *(undefined2 *)(param_1 + 0x14));
          }
          (**(code **)(*(int *)(param_1 + 0x38) + 8))
                    (*(int *)(param_1 + 0x10) + 0x58,*(undefined2 *)(param_1 + 0x14),
                     *(undefined2 *)(*(int *)(param_1 + 0x38) + 2),*(undefined *)(param_1 + 0x3f));
          return;
        }
        goto LAB_0010ff18;
      }
      if (param_2 != 0x1e) {
        if (param_2 < 0x1f) {
          if (param_2 != 0x1b) {
            return;
          }
          l2cu_release_ccb(param_1);
          return;
        }
        if (param_2 == 0x20) {
          iVar7 = btsnd_hcic_disconnect(*(undefined2 *)(*(int *)(param_1 + 0x10) + 0x28),5);
          if (iVar7 != 0) {
            return;
          }
          if (2 < l2cb[0]) {
            LogMsg(0x80002,"L2CAP - Calling btsnd_hcic_disconnect for handle %i failed",
                   *(undefined2 *)(*(int *)(param_1 + 0x10) + 0x28));
          }
          btu_start_timer(param_1 + 0x18,3,1);
          return;
        }
        if (param_2 != 0x21) {
          return;
        }
        btm_sec_l2cap_access_req
                  (*(int *)(param_1 + 0x10) + 0x58,*(undefined2 *)(*(int *)(param_1 + 0x38) + 2),
                   *(undefined2 *)(*(int *)(param_1 + 0x10) + 0x28),0,l2c_link_sec_comp + 1,param_1)
        ;
        return;
      }
    }
    GKI_freebuf(param_3);
    break;
  case 3:
    uVar4 = *(undefined2 *)(param_1 + 0x14);
    pcVar10 = *(code **)(*(int *)(param_1 + 0x38) + 0x1c);
    pcVar8 = *(code **)(*(int *)(param_1 + 0x38) + 0xc);
    if (3 < l2cb[0]) {
      LogMsg(0x80003,"L2CAP - st: W4_L2CAP_CON_RSP evt: %d",param_2);
    }
    if (param_2 != 0x13) {
      if (0x13 < param_2) {
        if (param_2 == 0x1b) {
          if (*(short *)(param_1 + 0x16) != 0) {
            l2cu_send_peer_disc_req();
            *(undefined4 *)(param_1 + 4) = 7;
            btu_start_timer(param_1 + 0x18,3,10);
            return;
          }
          l2cu_release_ccb(param_1);
          return;
        }
        if (param_2 < 0x1c) {
          if (param_2 != 0x14) {
            return;
          }
        }
        else if (param_2 != 0x1e) {
          if (param_2 != 0x20) {
            return;
          }
          if (2 < l2cb[0]) {
            LogMsg(0x80002,"L2CAP - Calling Connect_Cfm_Cb(), CID: 0x%04x, Timeout",
                   *(undefined2 *)(param_1 + 0x14));
          }
          l2cu_release_ccb(param_1);
          (*pcVar8)(uVar4,0xeeee);
          return;
        }
        GKI_freebuf(param_3);
        return;
      }
      if (param_2 == 0xb) {
        sVar3 = param_3[7];
        *(undefined4 *)(param_1 + 4) = 5;
        *(short *)(param_1 + 0x16) = sVar3;
        btu_start_timer(param_1 + 0x18,3,0x1e);
        if (2 < l2cb[0]) {
          LogMsg(0x80002,"L2CAP - Calling Connect_Cfm_Cb(), CID: 0x%04x, Success",
                 *(undefined2 *)(param_1 + 0x14));
        }
        (**(code **)(*(int *)(param_1 + 0x38) + 0xc))(uVar4,0);
        return;
      }
      if (param_2 < 0xc) {
        if (param_2 != 3) {
          return;
        }
        *(undefined4 *)(param_1 + 4) = 0;
        if ((((int)((uint)*(byte *)(param_1 + 0x40) << 0x1f) < 0) || (param_3 == (short *)0x0)) ||
           (*(char *)param_3 != '\x13')) {
          if (2 < l2cb[0]) {
            LogMsg(0x80002,"L2CAP - Calling Disconnect_Ind_Cb(), CID: 0x%04x  No Conf Needed",
                   *(undefined2 *)(param_1 + 0x14));
          }
          l2cu_release_ccb(param_1);
          (*pcVar10)(uVar4,0);
        }
        *(byte *)(param_1 + 0x40) = *(byte *)(param_1 + 0x40) | 1;
        return;
      }
      if (param_2 == 0xc) {
        *(short *)(param_1 + 0x16) = param_3[7];
        btu_start_timer(param_1 + 0x18,3,0x78);
        if (*(int *)(*(int *)(param_1 + 0x38) + 0x10) == 0) {
          return;
        }
        if (2 < l2cb[0]) {
          LogMsg(0x80002,"L2CAP - Calling Connect_Pnd_Cb(), CID: 0x%04x",
                 *(undefined2 *)(param_1 + 0x14));
        }
        (**(code **)(*(int *)(param_1 + 0x38) + 0x10))(*(undefined2 *)(param_1 + 0x14));
        return;
      }
      if (param_2 != 0xd) {
        return;
      }
      if (2 < l2cb[0]) {
        LogMsg(0x80002,"L2CAP - Calling Connect_Cfm_Cb(), CID: 0x%04x, Failure Code: %d",
               *(undefined2 *)(param_1 + 0x14),param_3[5]);
      }
      l2cu_release_ccb(param_1);
      (*pcVar8)(uVar4,param_3[5]);
      return;
    }
    iVar7 = l2c_fcr_chk_chan_modes(param_1);
    if (iVar7 == 0) {
      l2cu_release_ccb(param_1);
      (*pcVar8)(uVar4,0xff);
      return;
    }
LAB_0011001e:
    btu_start_timer(param_1 + 0x18,3,0x3c);
    l2cu_send_peer_connect_req(param_1);
    break;
  case 4:
    uVar4 = *(undefined2 *)(param_1 + 0x14);
    pcVar8 = *(code **)(*(int *)(param_1 + 0x38) + 0x1c);
    if (3 < l2cb[0]) {
      LogMsg(0x80003,"L2CAP - st: W4_L2CA_CON_RSP evt: %d",param_2);
    }
    if (param_2 == 0x16) {
      if ((param_3 == (short *)0x0) || (param_3[5] == 0)) {
        l2cu_send_peer_connect_rsp(param_1,0,0);
        *(undefined4 *)(param_1 + 4) = 5;
        btu_start_timer(param_1 + 0x18,3,0x1e);
      }
      else {
        l2cu_send_peer_connect_rsp(param_1,param_3[5],param_3[6]);
        btu_start_timer(param_1 + 0x18,3,0x78);
      }
    }
    else {
      if (param_2 < 0x17) {
        if (param_2 == 0x13) {
          btu_start_timer(param_1 + 0x18,3,0x3c);
          if (2 < l2cb[0]) {
            LogMsg(0x80002,"L2CAP - Calling Connect_Ind_Cb(), CID: 0x%04x",
                   *(undefined2 *)(param_1 + 0x14));
          }
          (**(code **)(*(int *)(param_1 + 0x38) + 8))
                    (*(int *)(param_1 + 0x10) + 0x58,*(undefined2 *)(param_1 + 0x14),
                     *(undefined2 *)(*(int *)(param_1 + 0x38) + 2),*(undefined *)(param_1 + 0x3f));
          return;
        }
        if (param_2 != 0x14) {
          if (param_2 != 3) {
            return;
          }
          if (2 < l2cb[0]) {
            LogMsg(0x80002,"L2CAP - Calling Disconnect_Ind_Cb(), CID: 0x%04x  No Conf Needed",
                   *(undefined2 *)(param_1 + 0x14));
          }
          l2cu_release_ccb(param_1);
          (*pcVar8)(uVar4,0);
          return;
        }
      }
      else {
        if (param_2 == 0x1b) {
          l2cu_send_peer_disc_req(param_1);
          *(undefined4 *)(param_1 + 4) = 7;
          btu_start_timer(param_1 + 0x18,3,10);
          return;
        }
        if (param_2 < 0x1c) {
          if (param_2 != 0x17) {
            return;
          }
          l2cu_send_peer_connect_rsp(param_1,param_3[5],param_3[6]);
          l2cu_release_ccb(param_1);
          return;
        }
        if (param_2 != 0x1e) {
          if (param_2 != 0x20) {
            return;
          }
          l2cu_send_peer_connect_rsp(param_1,2,0);
          if (2 < l2cb[0]) {
            LogMsg(0x80002,"L2CAP - Calling Disconnect_Ind_Cb(), CID: 0x%04x  No Conf Needed",
                   *(undefined2 *)(param_1 + 0x14));
          }
          l2cu_release_ccb(param_1);
          (*pcVar8)(uVar4,0);
          return;
        }
      }
      GKI_freebuf(param_3);
    }
    break;
  case 5:
    uVar4 = *(undefined2 *)(param_1 + 0x14);
    pcVar8 = *(code **)(*(int *)(param_1 + 0x38) + 0x1c);
    if (3 < l2cb[0]) {
      LogMsg(0x80003,"L2CAP - st: CONFIG evt: %d",param_2);
    }
    switch(param_2) {
    case 3:
      if (2 < l2cb[0]) {
        LogMsg(0x80002,"L2CAP - Calling Disconnect_Ind_Cb(), CID: 0x%04x  No Conf Needed",
               *(undefined2 *)(param_1 + 0x14));
      }
      l2cu_release_ccb(param_1);
      (*pcVar8)(uVar4,0);
      break;
    case 0xe:
      iVar7 = l2cu_process_peer_cfg_req(param_1,param_3);
      if (iVar7 == 1) {
        if (3 < l2cb[0]) {
          LogMsg(0x80003,"L2CAP - Calling Config_Req_Cb(), CID: 0x%04x, C-bit %d",
                 *(undefined2 *)(param_1 + 0x14),param_3[0x22] & 1);
        }
        (**(code **)(*(int *)(param_1 + 0x38) + 0x14))(*(undefined2 *)(param_1 + 0x14),param_3);
        return;
      }
      if (iVar7 == 2) {
        if (3 < l2cb[0]) {
          LogMsg(0x80003,"L2CAP - incompatible configurations disconnect");
        }
        goto LAB_00110646;
      }
      if (3 < l2cb[0]) {
        LogMsg(0x80003,"L2CAP - incompatible configurations trying reconfig");
      }
      goto LAB_0011065c;
    case 0xf:
      l2cu_process_peer_cfg_rsp(param_1,param_3);
      if (*param_3 != 4) {
        bVar2 = *(byte *)(param_1 + 0x3d);
        *(byte *)(param_1 + 0x3d) = bVar2 | 2;
        if ((int)((uint)bVar2 << 0x1f) < 0) {
          if (*(char *)(param_1 + 0x6a) != *(char *)(param_1 + 0xb6)) {
            l2cu_send_peer_disc_req(param_1);
            if (1 < l2cb[0]) {
              LogMsg(0x80001,
                     "L2CAP - Calling Disconnect_Ind_Cb(Incompatible CFG), CID: 0x%04x  No Conf Need ed"
                     ,*(undefined2 *)(param_1 + 0x14));
            }
            l2cu_release_ccb(param_1);
            (*pcVar8)(uVar4,0);
            return;
          }
          *(byte *)(param_1 + 0x3d) = bVar2 | 6;
          *(undefined4 *)(param_1 + 4) = 6;
          l2c_link_adjust_chnl_allocation();
          btu_stop_timer(param_1 + 0x18);
          if (*(char *)(param_1 + 0xfe) != '\0') {
            l2c_fcr_start_timer(param_1);
          }
          if ((*(char *)(param_1 + 0x6a) == '\x03') &&
             ((*(short *)(param_1 + 0x70) == 0 || (*(short *)(param_1 + 0x6e) != 0)))) {
            l2c_fcr_adj_monitor_retran_timeout(param_1);
          }
          iVar7 = GKI_queue_is_empty(param_1 + 0xd8);
          if (iVar7 == 0) {
            l2c_link_check_send_pkts(*(undefined4 *)(param_1 + 0x10),0,0);
          }
        }
      }
      if (2 < l2cb[0]) {
        LogMsg(0x80002,"L2CAP - Calling Config_Rsp_Cb(), CID: 0x%04x",
               *(undefined2 *)(param_1 + 0x14));
      }
      (**(code **)(*(int *)(param_1 + 0x38) + 0x18))(*(undefined2 *)(param_1 + 0x14),param_3);
      break;
    case 0x10:
      btu_stop_timer(param_1 + 0x18);
      iVar7 = l2c_fcr_renegotiate_chan(param_1,param_3);
      if (iVar7 == 0) {
        if (2 < l2cb[0]) {
          LogMsg(0x80002,"L2CAP - Calling Config_Rsp_Cb(), CID: 0x%04x, Failure: %d",
                 *(undefined2 *)(param_1 + 0x14),*param_3);
        }
        (**(code **)(*(int *)(param_1 + 0x38) + 0x18))(*(undefined2 *)(param_1 + 0x14),param_3);
      }
      break;
    case 0x11:
      btu_start_timer(param_1 + 0x18,3,10);
      bVar2 = l2cb[0];
      *(undefined4 *)(param_1 + 4) = 8;
      if (2 < bVar2) {
        LogMsg(0x80002,"L2CAP - Calling Disconnect_Ind_Cb(), CID: 0x%04x  Conf Needed",
               *(undefined2 *)(param_1 + 0x14));
      }
      (**(code **)(*(int *)(param_1 + 0x38) + 0x1c))(*(undefined2 *)(param_1 + 0x14),1);
      break;
    case 0x14:
      if (2 < l2cb[0]) {
        LogMsg(0x80002,"L2CAP - Calling DataInd_Cb(), CID: 0x%04x",*(undefined2 *)(param_1 + 0x14));
      }
      uVar6 = (uint)*(ushort *)(param_1 + 0x14);
      if (0x1f < (uVar6 - 4 & 0xffff)) {
        (**(code **)(*(int *)(param_1 + 0x38) + 0x28))(uVar6,param_3);
        return;
      }
      if (*(code **)(l2cb + (uVar6 - 4) * 0x1c + 0x244c) != (code *)0x0) {
        (**(code **)(l2cb + (uVar6 - 4) * 0x1c + 0x244c))
                  (uVar6,*(int *)(param_1 + 0x10) + 0x58,param_3);
        return;
      }
      goto LAB_001108fe;
    case 0x18:
      l2cu_process_our_cfg_req(param_1,param_3);
      l2cu_send_peer_config_req(param_1,param_3);
      btu_start_timer(param_1 + 0x18,3,0x1e);
      break;
    case 0x19:
      l2cu_process_our_cfg_rsp(param_1,param_3);
      bVar2 = (byte)param_3[0x22] & 1;
      if (((param_3[0x22] & 1U) == 0) && (*param_3 != 4)) {
        bVar1 = *(byte *)(param_1 + 0x3d);
        *(byte *)(param_1 + 0x92) = bVar2;
        *(byte *)(param_1 + 0xb0) = bVar2;
        *(byte *)(param_1 + 0x96) = bVar2;
        *(byte *)(param_1 + 0x3d) = bVar1 | 1;
        if ((int)((uint)bVar1 << 0x1e) < 0) {
          if (*(char *)(param_1 + 0x6a) != *(char *)(param_1 + 0xb6)) {
            l2cu_send_peer_disc_req(param_1);
            if (1 < l2cb[0]) {
              LogMsg(0x80001,
                     "L2CAP - Calling Disconnect_Ind_Cb(Incompatible CFG), CID: 0x%04x  No Conf Need ed"
                     ,*(undefined2 *)(param_1 + 0x14));
            }
            l2cu_release_ccb(param_1);
            (*pcVar8)(uVar4,0);
            return;
          }
          *(byte *)(param_1 + 0x3d) = bVar1 | 5;
          *(undefined4 *)(param_1 + 4) = 6;
          l2c_link_adjust_chnl_allocation();
          btu_stop_timer(param_1 + 0x18);
        }
        l2cu_send_peer_config_rsp(param_1,param_3);
        if (*(char *)(param_1 + 0xfe) != '\0') {
          l2c_fcr_start_timer(param_1);
        }
        if (*(int *)(param_1 + 4) != 6) {
          return;
        }
        iVar7 = GKI_queue_is_empty(param_1 + 0xd8);
        if (iVar7 != 0) {
          return;
        }
        l2c_link_check_send_pkts(*(undefined4 *)(param_1 + 0x10),0,0);
        return;
      }
LAB_0011065c:
      l2cu_send_peer_config_rsp(param_1,param_3);
      break;
    case 0x1a:
      l2cu_send_peer_config_rsp(param_1,param_3);
      btu_start_timer(param_1 + 0x18,3,0x1e);
      break;
    case 0x1b:
      l2cu_send_peer_disc_req(param_1);
      *(undefined4 *)(param_1 + 4) = 7;
      btu_start_timer(param_1 + 0x18,3,10);
      break;
    case 0x1e:
      if ((int)((uint)*(byte *)(param_1 + 0x3d) << 0x1e) < 0) {
        l2c_enqueue_peer_data(param_1,param_3);
        return;
      }
LAB_001108fe:
      GKI_freebuf(param_3);
      break;
    case 0x20:
      if (*(int *)(param_1 + 0x10) == 0) {
        btif_dm_log_collector_cback
                  ("%s -- l2c_csm_config :: L2CEVT_TIMEOUT. Skip release p_ccb.","l2c_csm.c");
      }
      else {
        l2cu_send_peer_disc_req(param_1);
        if (2 < l2cb[0]) {
          LogMsg(0x80002,"L2CAP - Calling Disconnect_Ind_Cb(), CID: 0x%04x  No Conf Needed",
                 *(undefined2 *)(param_1 + 0x14));
        }
        l2cu_release_ccb(param_1);
        (*pcVar8)(uVar4,0);
      }
    }
    break;
  case 6:
    uVar4 = *(undefined2 *)(param_1 + 0x14);
    if (3 < l2cb[0]) {
      LogMsg(0x80003,"L2CAP - st: OPEN evt: %d",param_2);
    }
    if (param_2 == 0x14) {
      if (*(int *)(param_1 + 0x38) == 0) {
        return;
      }
      pcVar8 = *(code **)(*(int *)(param_1 + 0x38) + 0x28);
      if (pcVar8 == (code *)0x0) {
        return;
      }
      (*pcVar8)(*(undefined2 *)(param_1 + 0x14),param_3);
      return;
    }
    if (0x14 < param_2) {
      if (param_2 == 0x1e) {
        l2c_enqueue_peer_data(param_1,param_3);
        l2c_link_check_send_pkts(*(undefined4 *)(param_1 + 0x10),0,0);
        return;
      }
      if (0x1e < param_2) {
        if (param_2 == 0x20) {
          if (*(char *)(param_1 + 0xb6) != '\x03') {
            return;
          }
          l2c_fcr_proc_tout(param_1);
          return;
        }
        if (param_2 != 0x22) {
          return;
        }
        l2c_fcr_proc_ack_tout(param_1);
        return;
      }
      if (param_2 == 0x18) {
        *(undefined4 *)(param_1 + 4) = 5;
        *(byte *)(param_1 + 0x3d) = *(byte *)(param_1 + 0x3d) & 0xfc;
        l2cu_process_our_cfg_req(param_1,param_3);
        l2cu_send_peer_config_req(param_1,param_3);
        btu_start_timer(param_1 + 0x18,3,0x1e);
        return;
      }
      if (param_2 != 0x1b) {
        return;
      }
      memset(auStack_34,0,10);
      BTM_SetPowerMode(0x80,*(int *)(param_1 + 0x10) + 0x58,auStack_34);
      l2cu_send_peer_disc_req(param_1);
      *(undefined4 *)(param_1 + 4) = 7;
      btu_start_timer(param_1 + 0x18,3,10);
      return;
    }
    if (param_2 == 6) {
      pcVar8 = *(code **)(*(int *)(param_1 + 0x38) + 0x24);
      if (pcVar8 == (code *)0x0) {
        return;
      }
      (*pcVar8)(*(int *)(param_1 + 0x10) + 0x58);
      return;
    }
    if (param_2 < 7) {
      if (param_2 != 3) {
        return;
      }
      if (2 < l2cb[0]) {
        LogMsg(0x80002,"L2CAP - Calling Disconnect_Ind_Cb(), CID: 0x%04x  No Conf Needed",
               *(undefined2 *)(param_1 + 0x14));
      }
      l2cu_release_ccb(param_1);
      if (*(int *)(param_1 + 0x38) == 0) {
        return;
      }
      (**(code **)(*(int *)(param_1 + 0x38) + 0x1c))(uVar4,0);
      return;
    }
    if (param_2 != 0xe) {
      if (param_2 != 0x11) {
        return;
      }
      memset(auStack_34,0,10);
      BTM_SetPowerMode(0x80,*(int *)(param_1 + 0x10) + 0x58,auStack_34);
      *(undefined4 *)(param_1 + 4) = 8;
      btu_start_timer(param_1 + 0x18,3,10);
      if (2 < l2cb[0]) {
        LogMsg(0x80002,"L2CAP - Calling Disconnect_Ind_Cb(), CID: 0x%04x  Conf Needed",
               *(undefined2 *)(param_1 + 0x14));
      }
      (**(code **)(*(int *)(param_1 + 0x38) + 0x1c))(*(undefined2 *)(param_1 + 0x14),1);
      return;
    }
    bVar2 = *(byte *)(param_1 + 0x3d);
    uVar9 = *(undefined4 *)(param_1 + 4);
    *(undefined4 *)(param_1 + 4) = 5;
    *(byte *)(param_1 + 0x3d) = bVar2 & 0xfc;
    btu_start_timer(param_1 + 0x18,3,0x1e);
    iVar7 = l2cu_process_peer_cfg_req(param_1,param_3);
    if (iVar7 == 1) {
      (**(code **)(*(int *)(param_1 + 0x38) + 0x14))(*(undefined2 *)(param_1 + 0x14),param_3);
      return;
    }
    if (iVar7 == 0) {
      btu_stop_timer(param_1 + 0x18);
      *(undefined4 *)(param_1 + 4) = uVar9;
      *(byte *)(param_1 + 0x3d) = bVar2;
      l2cu_send_peer_config_rsp(param_1,param_3);
      return;
    }
LAB_00110646:
    l2cu_disconnect_chnl(param_1);
    break;
  case 7:
    uVar4 = *(undefined2 *)(param_1 + 0x14);
    pcVar8 = *(code **)(*(int *)(param_1 + 0x38) + 0x20);
    if (3 < l2cb[0]) {
      LogMsg(0x80003,"L2CAP - st: W4_L2CAP_DISC_RSP evt: %d",param_2);
    }
    if (param_2 == 0x12) {
      l2cu_release_ccb(param_1);
      if (pcVar8 == (code *)0x0) {
        return;
      }
      if (2 < l2cb[0]) {
        LogMsg(0x80002,"L2CAP - Calling DisconnectCfm_Cb(), CID: 0x%04x",uVar4);
      }
      (*pcVar8)(uVar4,0);
      return;
    }
    if (param_2 < 0x13) {
      if (param_2 != 3) {
        if (param_2 != 0x11) {
          return;
        }
        l2cu_send_peer_disc_rsp
                  (*(undefined4 *)(param_1 + 0x10),*(undefined *)(param_1 + 0x3f),
                   *(undefined2 *)(param_1 + 0x14),*(undefined2 *)(param_1 + 0x16));
        l2cu_release_ccb(param_1);
        if (pcVar8 == (code *)0x0) {
          return;
        }
        if (2 < l2cb[0]) {
          LogMsg(0x80002,"L2CAP - Calling DisconnectCfm_Cb(), CID: 0x%04x",uVar4);
        }
        (*pcVar8)(uVar4,0);
        return;
      }
LAB_00110c02:
      l2cu_release_ccb(param_1);
      if (pcVar8 != (code *)0x0) {
        if (2 < l2cb[0]) {
          LogMsg(0x80002,"L2CAP - Calling DisconnectCfm_Cb(), CID: 0x%04x",uVar4);
        }
        (*pcVar8)(uVar4,0xeeee);
      }
    }
    else {
      if (param_2 != 0x1e) {
        if (param_2 == 0x20) goto LAB_00110c02;
        if (param_2 != 0x14) {
          return;
        }
      }
      GKI_freebuf(param_3);
    }
    break;
  case 8:
    uVar4 = *(undefined2 *)(param_1 + 0x14);
    pcVar8 = *(code **)(*(int *)(param_1 + 0x38) + 0x1c);
    if (3 < l2cb[0]) {
      LogMsg(0x80003,"L2CAP - st: W4_L2CA_DISC_RSP evt: %d",param_2);
    }
    if (param_2 < 0x1d) {
      if (0x1a < param_2) {
        l2cu_send_peer_disc_rsp
                  (*(undefined4 *)(param_1 + 0x10),*(undefined *)(param_1 + 0x3f),
                   *(undefined2 *)(param_1 + 0x14),*(undefined2 *)(param_1 + 0x16));
        l2cu_release_ccb(param_1);
        return;
      }
      if (param_2 == 3) {
        if (2 < l2cb[0]) {
          LogMsg(0x80002,"L2CAP - Calling Disconnect_Ind_Cb(), CID: 0x%04x  No Conf Needed",
                 *(undefined2 *)(param_1 + 0x14));
        }
        l2cu_release_ccb(param_1);
        (*pcVar8)(uVar4,0);
        return;
      }
      if (param_2 != 0x14) {
        return;
      }
    }
    else if (param_2 != 0x1e) {
      if (param_2 != 0x20) {
        return;
      }
      l2cu_send_peer_disc_rsp
                (*(undefined4 *)(param_1 + 0x10),*(undefined *)(param_1 + 0x3f),
                 *(undefined2 *)(param_1 + 0x14),*(undefined2 *)(param_1 + 0x16));
      if (2 < l2cb[0]) {
        LogMsg(0x80002,"L2CAP - Calling Disconnect_Ind_Cb(), CID: 0x%04x  No Conf Needed",
               *(undefined2 *)(param_1 + 0x14));
      }
      l2cu_release_ccb(param_1);
      (*pcVar8)(uVar4,0);
      return;
    }
    GKI_freebuf(param_3);
    break;
  default:
    if (4 < l2cb[0]) {
      LogMsg(0x80004,"Unhandled event! event = %d",param_2);
    }
  }
  return;
}

