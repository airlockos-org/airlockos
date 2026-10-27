import Clutter from 'gi://Clutter';
import Gio from 'gi://Gio';
import GObject from 'gi://GObject';
import St from 'gi://St';

import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as ModalDialog from 'resource:///org/gnome/shell/ui/modalDialog.js';
import * as SystemActions from 'resource:///org/gnome/shell/misc/systemActions.js';
import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';

const HOST_POWEROFF = '@hostPoweroff@';

const HostPowerOffDialog = GObject.registerClass(
class HostPowerOffDialog extends ModalDialog.ModalDialog {
    _init() {
        super._init({destroyOnClose: false});

        this.contentLayout.add_child(new St.Label({
            text: 'Power Off',
            style_class: 'end-session-dialog-subject',
        }));
        this.contentLayout.add_child(new St.Label({
            text: 'Power off this computer and all running VMs?',
            style_class: 'end-session-dialog-description',
        }));
        this.setButtons([
            {
                label: 'Cancel',
                action: () => this.close(),
                key: Clutter.KEY_Escape,
            },
            {
                label: 'Power Off',
                action: () => this._powerOff(),
                default: true,
            },
        ]);
    }

    _powerOff() {
        this.close();

        try {
            const process = Gio.Subprocess.new(
                [HOST_POWEROFF], Gio.SubprocessFlags.NONE);
            process.wait_check_async(null, (source, result) => {
                try {
                    source.wait_check_finish(result);
                } catch (error) {
                    logError(error, 'Airlock host power-off request failed');
                    Main.notifyError(
                        'Power Off Failed',
                        'Dom0 did not confirm the power-off request. The computer may remain on.');
                }
            });
        } catch (error) {
            logError(error, 'Unable to start the Airlock host power-off request');
            Main.notifyError(
                'Power Off Failed',
                'The request could not be started. The computer remains on.');
        }
    }
});

export default class AirlockHostPowerOffExtension extends Extension {
    enable() {
        this._systemActions = SystemActions.getDefault();
        this._originalActivatePowerOff = this._systemActions.activatePowerOff;
        this._dialog = new HostPowerOffDialog();

        this._systemActions.activatePowerOff = () => {
            if (!this._systemActions.canPowerOff)
                throw new Error('The power-off action is not available');

            this._dialog.open();
        };
    }

    disable() {
        if (this._systemActions)
            this._systemActions.activatePowerOff = this._originalActivatePowerOff;

        this._dialog?.destroy();
        this._dialog = null;
        this._systemActions = null;
        this._originalActivatePowerOff = null;
    }
}
