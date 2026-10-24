// Exercise real JavaScript models and Shell controllers through a Rust-owned process.
const scenario=JSON.parse(process.env.AIRLOCK_JS_ARGUMENTS ?? "{}");
switch(process.env.AIRLOCK_JS_SCENARIO) {
case "only_occupied_application_workspaces_form_groups": {
const a={},b={},identities=new Map([[a,[]],[b,[LOCAL,{kind:'vm',name:'sys-gui'}]]]);
assert.deepEqual(groupOccupiedWorkspaces([], [a,b], identities, inventory), []);
identities.set(a,[{kind:'vm',name:'usr-home',color:'#ffffff'}]);
const groups=groupOccupiedWorkspaces([], [a,b], identities, inventory);
assert.equal(groups.length,1);assert.equal(groups[0].key,HOME);
assert.equal(groups[0].color,'#3465a4');assert.deepEqual(groups[0].slots,[a]);
assert.equal(groups.some(g=>g.name==='usr-assistant'),false);

break;
}
case "groups_keep_order_and_drop_closed_workspaces": {
const a={},b={},c={},d={};
const home={kind:'vm',name:'usr-home'},agent={kind:'vm',name:'usr-assistant'};
const identities=new Map([[a,[home]],[b,[agent]],[c,[home]],[d,[agent]]]);
let groups=groupOccupiedWorkspaces([], [a,b,c,d], identities, inventory);
assert.deepEqual(groups.map(g=>g.slots),[[a,c],[b,d]]);
groups[0].lastUsed=c;
groups=groupOccupiedWorkspaces(groups,[b,a,d,c],identities,inventory);
assert.deepEqual(groups.map(g=>g.key),[HOME,AGENT]);assert.equal(groups[0].lastUsed,c);
identities.set(a,[]);identities.set(c,[]);
groups=groupOccupiedWorkspaces(groups,[b,a,d,c],identities,inventory);
assert.deepEqual(groups.map(g=>g.key),[AGENT]);

break;
}
case "mixed_and_unknown_windows_use_neutral_identity": {
const description=describeWorkspace([
 {kind:'vm',name:'usr-home'}, {kind:'vm',name:'usr-assistant'},LOCAL],inventory);
assert.equal(description.kind,'mixed');assert.equal(description.color,'#888888');
assert.deepEqual(description.names,['usr-assistant','usr-home']);
assert.equal(describeWorkspace([UNKNOWN],inventory).kind,'unknown');
assert.equal(describeWorkspace([LOCAL],inventory),null);

break;
}
case "controller_keeps_native_activities_and_removes_empty_slots": {
const homeWindow=new Window(wm.workspaces[0]),agentWindow=new Window(wm.workspaces[1]);
actors.push({meta_window:homeWindow},{meta_window:agentWindow});
const ext=new Controller();ext.enable();finishInventory();
ext._identities.set(homeWindow,{kind:'vm',name:'usr-home'});
ext._identities.set(agentWindow,{kind:'vm',name:'usr-assistant'});ext._sync();
assert.equal(activities.get_first_child(),nativeIndicators);
assert.equal(activities.reactive,true);assert.equal(activities.accessible_name,'Activities');
assert.equal(shellMocks.Main.panel.placement.side,'right');
assert.equal(shellMocks.Main.panel.placement.index,0);
assert.equal(homeWindow.moves,0);assert.equal(agentWindow.moves,0);
assert.equal(ext._groups.length,2);assert.equal(ext._tabs.length,2);
ext._tabs[1].button.emit('clicked');assert.equal(wm.current,agentWindow.workspace);
activities._clickGesture.emit('recognize');assert.equal(overview.toggles,1);
const homeTab=ext._tabs[0];homeTab.button.hover=true;homeTab.button.emit('notify::hover');
sources.get(ext._tooltipSource)();assert.match(ext._tooltip.text,/usr-home/);
assert.equal(ext._tooltip.visible,true);
agentWindow.emit('unmanaged');allWindows.delete(agentWindow);ext._sync();
assert.equal(ext._groups.length,1);assert.equal(wm.n_workspaces,1);
homeWindow.emit('unmanaged');allWindows.delete(homeWindow);ext._sync();
assert.equal(ext._groups.length,0);assert.equal(wm.n_workspaces,1);
assert.equal(ext._indicator.visible,false);
ext.disable();assert.equal(settings.get('org.gnome.mutter')['dynamic-workspaces'],true);

break;
}
case "multiple_slots_stay_contiguous_and_foreign_moves_are_blocked": {
const homeWindow=new Window(wm.workspaces[0]),agentWindow=new Window(wm.workspaces[1]);
actors.push({meta_window:homeWindow},{meta_window:agentWindow});
const ext=new Controller();ext.enable();finishInventory();
ext._identities.set(homeWindow,{kind:'vm',name:'usr-home'});
ext._identities.set(agentWindow,{kind:'vm',name:'usr-assistant'});ext._sync();
const second=new Window(homeWindow.workspace);ext._watch(second);
ext._identities.set(second,{kind:'vm',name:'usr-home'});ext._splitWindow(second);ext._sync();
assert.deepEqual(ext._groups.map(g=>g.slots.length),[2,1]);
assert.equal(agentWindow.workspace.index(),2);
agentWindow.change_workspace(second.workspace);ext._sync();
assert.equal(agentWindow.workspace.index(),2);assert.equal(agentWindow.moves,0);
assert.equal(ext._groups.length,2);assert.equal(ext._groups[0].key,HOME);
assert.equal(ext._groups[0].slots.length,2);
assert.equal(ext._tabs[1].button._delegate.acceptDrop({metaWindow:agentWindow}),false);
second.change_workspace(homeWindow.workspace);assert.equal(second.workspace,homeWindow.workspace);
ext.disable();

break;
}
case "overview_decoration_tints_hover_labels_and_cleanup": {
const homeWindow=new Window(wm.workspaces[0]),agentWindow=new Window(wm.workspaces[1]);
actors.push({meta_window:homeWindow},{meta_window:agentWindow});
const existing=new WorkspacePreview(homeWindow.workspace);
overview._overview.controls._workspacesDisplay._workspacesViews=[{_workspaces:[existing]}];
const originalInit=WorkspacePreview.prototype._init;
const ext=new Controller();ext.enable();finishInventory();
ext._identities.set(homeWindow,{kind:'vm',name:'usr-home'});
ext._identities.set(agentWindow,{kind:'vm',name:'usr-assistant'});ext._sync();
const thumbnail=new ThumbnailPreview(agentWindow.workspace);
assert.equal(ext._overviewActors.size,2);
assert.match(ext._overviewActors.get(existing).border.style,/#3465a4/);
assert.match(ext._overviewActors.get(thumbnail).border.style,/#cc0000/);
assert.equal(ext._overviewActors.get(thumbnail).border.reactive,false);
const agent=ext._tabs[1];assert.match(agent.button.style,/rgba\(204,0,0,0.35\)/);
agent.button.hover=true;agent.button.emit('notify::hover');assert.match(agent.button.style,/,0.45\)/);
agent.button.emit('clicked');assert.match(agent.button.style,/,0.55\)/);
overview.visible=true;thumbnail.hover=true;thumbnail.emit('notify::hover');
sources.get(ext._tooltipSource)();assert.match(ext._tooltip.text,/usr-assistant/);
overview.emit('window-drag-begin');assert.equal(ext._tooltip.visible,false);
thumbnail.emit('notify::hover');assert.equal(ext._tooltipSource,0);
overview.emit('window-drag-end');
const record=ext._overviewActors.get(existing);ext.disable();
assert.equal(record.border.destroyed,true);assert.equal(existing.reactive,false);
assert.equal(WorkspacePreview.prototype._init,originalInit);

break;
}
case "new_control_review_switches_workspace_and_focuses_once": {
// Identity is supplied at the existing trusted-reader boundary. Guest-provided
// class/title metadata deliberately remains independent for spoofing tests.
function reviewDesktop(){
 const home=new Window(wm.workspaces[0]),terminal=new Window(wm.workspaces[1]);
 home.origin={kind:'vm',name:'usr-home'};terminal.origin={kind:'vm',name:'sys-ctrl'};
 actors.push({meta_window:home},{meta_window:terminal});
 const ext=new Controller();
 ext._resolveSync=window=>window.origin??UNKNOWN;
 ext._resolve=async window=>window.origin??UNKNOWN;
 ext.enable();finishInventory();
 ext._identities.set(home,home.origin);ext._identities.set(terminal,terminal.origin);
 ext._sync();home.workspace.activate();
 return {ext,home,terminal};
}
function openReview(ext,{origin={kind:'vm',name:'sys-ctrl'},wmClass='sys-ctrl:airlock-sys-ctrl-gui',kind=0,transient=false}={}){
 const window=new Window(wm.current,kind);
 Object.assign(window,{origin,wmClass,parent:transient?[...allWindows][0]:null,title:'Airlock Control'});
 actors.push({meta_window:window});
 display.emit('window-created',window);
 return window;
}
const mapWindow=window=>global.window_manager.emit('map',{meta_window:window});
const wmClass=scenario.wm_class;
const {ext,home,terminal}=reviewDesktop();
const review=openReview(ext,{wmClass});
assert.equal(review.workspace,terminal.workspace);
assert.equal(wm.current,home.workspace);
assert.equal(activations.length,0);
overview.visible=true;
mapWindow(review);
assert.equal(wm.current,review.workspace);
assert.equal(display.focus_window,review);
assert.equal(overview.visible,false);
assert.equal(activations.length,1);
home.workspace.activate();
review.emit('notify::wm-class');
mapWindow(review);ext._sync();
assert.equal(activations.length,1);
assert.equal(wm.current,home.workspace);
const next=openReview(ext,{wmClass});mapWindow(next);
assert.equal(activations.length,2);
assert.equal(display.focus_window,next);
ext.disable();

break;
}
case "other_windows_cannot_request_review_focus": {
// Identity is supplied at the existing trusted-reader boundary. Guest-provided
// class/title metadata deliberately remains independent for spoofing tests.
function reviewDesktop(){
 const home=new Window(wm.workspaces[0]),terminal=new Window(wm.workspaces[1]);
 home.origin={kind:'vm',name:'usr-home'};terminal.origin={kind:'vm',name:'sys-ctrl'};
 actors.push({meta_window:home},{meta_window:terminal});
 const ext=new Controller();
 ext._resolveSync=window=>window.origin??UNKNOWN;
 ext._resolve=async window=>window.origin??UNKNOWN;
 ext.enable();finishInventory();
 ext._identities.set(home,home.origin);ext._identities.set(terminal,terminal.origin);
 ext._sync();home.workspace.activate();
 return {ext,home,terminal};
}
function openReview(ext,{origin={kind:'vm',name:'sys-ctrl'},wmClass='sys-ctrl:airlock-sys-ctrl-gui',kind=0,transient=false}={}){
 const window=new Window(wm.current,kind);
 Object.assign(window,{origin,wmClass,parent:transient?[...allWindows][0]:null,title:'Airlock Control'});
 actors.push({meta_window:window});
 display.emit('window-created',window);
 return window;
}
const mapWindow=window=>global.window_manager.emit('map',{meta_window:window});
const options=scenario.options;
const {ext,home}=reviewDesktop();
const window=openReview(ext,options);mapWindow(window);
window.emit('notify::wm-class');ext._sync();
assert.equal(activations.length,0);
assert.equal(wm.current,home.workspace);
ext.disable();

break;
}
case "review_focus_waits_for_identity_mapping_and_class": {
// Identity is supplied at the existing trusted-reader boundary. Guest-provided
// class/title metadata deliberately remains independent for spoofing tests.
function reviewDesktop(){
 const home=new Window(wm.workspaces[0]),terminal=new Window(wm.workspaces[1]);
 home.origin={kind:'vm',name:'usr-home'};terminal.origin={kind:'vm',name:'sys-ctrl'};
 actors.push({meta_window:home},{meta_window:terminal});
 const ext=new Controller();
 ext._resolveSync=window=>window.origin??UNKNOWN;
 ext._resolve=async window=>window.origin??UNKNOWN;
 ext.enable();finishInventory();
 ext._identities.set(home,home.origin);ext._identities.set(terminal,terminal.origin);
 ext._sync();home.workspace.activate();
 return {ext,home,terminal};
}
function openReview(ext,{origin={kind:'vm',name:'sys-ctrl'},wmClass='sys-ctrl:airlock-sys-ctrl-gui',kind=0,transient=false}={}){
 const window=new Window(wm.current,kind);
 Object.assign(window,{origin,wmClass,parent:transient?[...allWindows][0]:null,title:'Airlock Control'});
 actors.push({meta_window:window});
 display.emit('window-created',window);
 return window;
}
const mapWindow=window=>global.window_manager.emit('map',{meta_window:window});
const order=scenario.order;
const {ext,home}=reviewDesktop();
const review=openReview(ext,{origin:UNKNOWN,wmClass:order==='class-after-map'?null:'sys-ctrl:airlock-sys-ctrl-gui'});
if(order!=='identity-before-map')mapWindow(review);
assert.equal(activations.length,0);
review.origin={kind:'vm',name:'sys-ctrl'};
await ext._scan();
if(order==='identity-before-map'){
 assert.equal(activations.length,0);
 mapWindow(review);
}else if(order==='class-after-map'){
 assert.equal(activations.length,0);
 review.wmInstance='sys-ctrl:airlock-sys-ctrl-gui';review.emit('notify::wm-class');
}
assert.equal(activations.length,1);
assert.equal(wm.current,review.workspace);
assert.equal(display.focus_window,review);
home.workspace.activate();await ext._scan();
assert.equal(activations.length,1);
assert.equal(wm.current,home.workspace);
ext.disable();

break;
}
case "review_waits_for_unlocked_desktop": {
// Identity is supplied at the existing trusted-reader boundary. Guest-provided
// class/title metadata deliberately remains independent for spoofing tests.
function reviewDesktop(){
 const home=new Window(wm.workspaces[0]),terminal=new Window(wm.workspaces[1]);
 home.origin={kind:'vm',name:'usr-home'};terminal.origin={kind:'vm',name:'sys-ctrl'};
 actors.push({meta_window:home},{meta_window:terminal});
 const ext=new Controller();
 ext._resolveSync=window=>window.origin??UNKNOWN;
 ext._resolve=async window=>window.origin??UNKNOWN;
 ext.enable();finishInventory();
 ext._identities.set(home,home.origin);ext._identities.set(terminal,terminal.origin);
 ext._sync();home.workspace.activate();
 return {ext,home,terminal};
}
function openReview(ext,{origin={kind:'vm',name:'sys-ctrl'},wmClass='sys-ctrl:airlock-sys-ctrl-gui',kind=0,transient=false}={}){
 const window=new Window(wm.current,kind);
 Object.assign(window,{origin,wmClass,parent:transient?[...allWindows][0]:null,title:'Airlock Control'});
 actors.push({meta_window:window});
 display.emit('window-created',window);
 return window;
}
const mapWindow=window=>global.window_manager.emit('map',{meta_window:window});
const mode=scenario.mode;
const {ext,home}=reviewDesktop();
shellMocks.Main.sessionMode[mode]=true;
const review=openReview(ext);mapWindow(review);
assert.equal(activations.length,0);
assert.equal(wm.current,home.workspace);
shellMocks.Main.sessionMode[mode]=false;
shellMocks.Main.sessionMode.emit('updated');
assert.equal(activations.length,1);
assert.equal(display.focus_window,review);
home.workspace.activate();shellMocks.Main.sessionMode.emit('updated');
assert.equal(activations.length,1);
assert.equal(wm.current,home.workspace);
ext.disable();

break;
}
case "extension_reload_does_not_refocus_existing_review": {
// Identity is supplied at the existing trusted-reader boundary. Guest-provided
// class/title metadata deliberately remains independent for spoofing tests.
function reviewDesktop(){
 const home=new Window(wm.workspaces[0]),terminal=new Window(wm.workspaces[1]);
 home.origin={kind:'vm',name:'usr-home'};terminal.origin={kind:'vm',name:'sys-ctrl'};
 actors.push({meta_window:home},{meta_window:terminal});
 const ext=new Controller();
 ext._resolveSync=window=>window.origin??UNKNOWN;
 ext._resolve=async window=>window.origin??UNKNOWN;
 ext.enable();finishInventory();
 ext._identities.set(home,home.origin);ext._identities.set(terminal,terminal.origin);
 ext._sync();home.workspace.activate();
 return {ext,home,terminal};
}
function openReview(ext,{origin={kind:'vm',name:'sys-ctrl'},wmClass='sys-ctrl:airlock-sys-ctrl-gui',kind=0,transient=false}={}){
 const window=new Window(wm.current,kind);
 Object.assign(window,{origin,wmClass,parent:transient?[...allWindows][0]:null,title:'Airlock Control'});
 actors.push({meta_window:window});
 display.emit('window-created',window);
 return window;
}
const mapWindow=window=>global.window_manager.emit('map',{meta_window:window});

const {ext,home}=reviewDesktop();
const review=openReview(ext);mapWindow(review);
assert.equal(activations.length,1);
ext.disable();home.workspace.activate();
ext.enable();finishInventory();await ext._scan();mapWindow(review);
review.emit('notify::wm-class');
assert.equal(activations.length,1);
assert.equal(wm.current,home.workspace);
ext.disable();

break;
}
case "pending_review_focus_is_cancelled_on_cleanup": {
// Identity is supplied at the existing trusted-reader boundary. Guest-provided
// class/title metadata deliberately remains independent for spoofing tests.
function reviewDesktop(){
 const home=new Window(wm.workspaces[0]),terminal=new Window(wm.workspaces[1]);
 home.origin={kind:'vm',name:'usr-home'};terminal.origin={kind:'vm',name:'sys-ctrl'};
 actors.push({meta_window:home},{meta_window:terminal});
 const ext=new Controller();
 ext._resolveSync=window=>window.origin??UNKNOWN;
 ext._resolve=async window=>window.origin??UNKNOWN;
 ext.enable();finishInventory();
 ext._identities.set(home,home.origin);ext._identities.set(terminal,terminal.origin);
 ext._sync();home.workspace.activate();
 return {ext,home,terminal};
}
function openReview(ext,{origin={kind:'vm',name:'sys-ctrl'},wmClass='sys-ctrl:airlock-sys-ctrl-gui',kind=0,transient=false}={}){
 const window=new Window(wm.current,kind);
 Object.assign(window,{origin,wmClass,parent:transient?[...allWindows][0]:null,title:'Airlock Control'});
 actors.push({meta_window:window});
 display.emit('window-created',window);
 return window;
}
const mapWindow=window=>global.window_manager.emit('map',{meta_window:window});
const cleanup=scenario.cleanup;
const {ext,home}=reviewDesktop();
shellMocks.Main.sessionMode.isLocked=true;
const review=openReview(ext);mapWindow(review);
if(cleanup==='closed'){
 review.emit('unmanaged');allWindows.delete(review);
}else ext.disable();
shellMocks.Main.sessionMode.isLocked=false;
shellMocks.Main.sessionMode.emit('updated');
review.emit('notify::wm-class');mapWindow(review);
assert.equal(activations.length,0);
assert.equal(wm.current,home.workspace);
if(cleanup==='closed')ext.disable();

break;
}
default: throw new Error("unknown JavaScript scenario");
}
