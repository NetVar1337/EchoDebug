// EchoDebug live sync for Ghidra 11.1+ (CodeBrowser).
//
// Run once to connect the current program to the EchoDebug relay (ws://127.0.0.1:47110/sync),
// run again to disconnect. The cursor follows EchoDebug and drives it; user labels / function
// names and EOL comments go both ways; struct types pushed from EchoDebug are parsed with the C
// parser into the program's data types. Locations travel as program name + RVA (address - image
// base), so a rebased program still lines up with the live module.
//
// Install: copy this file into a script directory (e.g. ~/ghidra_scripts), then Window > Script
// Manager > EchoDebug > EchoDebugSync.java (or Tools > EchoDebug Sync). The relay token is read
// from the EchoDebug config folder (relay-token) or ECHODEBUG_TOKEN; ECHODEBUG_PORT sets the port.
//
// @category EchoDebug
// @menupath Tools.EchoDebug Sync
// @keybinding ctrl alt E
// @runtime Java

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.listener.FieldLocationListener;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.GoToService;
import ghidra.app.util.cparser.C.CParser;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.CommentChangeRecord;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.program.util.ProgramEvent;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.Swing;

public class EchoDebugSync extends GhidraScript {

	/** One session per tool; running the script again stops it. */
	private static final Map<PluginTool, Session> SESSIONS = new ConcurrentHashMap<>();

	@Override
	protected void run() throws Exception {
		PluginTool tool = state.getTool();
		if (tool == null || currentProgram == null) {
			printerr("EchoDebug sync needs the CodeBrowser with a program open");
			return;
		}
		Session running = SESSIONS.remove(tool);
		if (running != null) {
			running.stop();
			println("EchoDebug sync: stopped");
			return;
		}
		Session s = new Session(tool, currentProgram);
		SESSIONS.put(tool, s);
		s.start();
		println("EchoDebug sync: connecting to " + s.uri + " for " + s.module);
	}

	static String configDir() {
		String appdata = System.getenv("APPDATA");
		if (System.getProperty("os.name", "").toLowerCase().startsWith("windows") && appdata != null) {
			return Paths.get(appdata, "EchoDebug").toString();
		}
		String xdg = System.getenv("XDG_CONFIG_HOME");
		if (xdg != null && !xdg.isEmpty()) {
			return Paths.get(xdg, "EchoDebug").toString();
		}
		return Paths.get(System.getProperty("user.home"), ".config", "EchoDebug").toString();
	}

	static String token() {
		String t = System.getenv("ECHODEBUG_TOKEN");
		if (t != null && !t.trim().isEmpty()) {
			return t.trim();
		}
		try {
			Path p = Paths.get(configDir(), "relay-token");
			return Files.exists(p) ? Files.readString(p).trim() : null;
		}
		catch (Exception e) {
			return null;
		}
	}

	static int port() {
		try {
			return Integer.parseInt(System.getenv().getOrDefault("ECHODEBUG_PORT", "47110"));
		}
		catch (NumberFormatException e) {
			return 47110;
		}
	}

	static final class Session implements WebSocket.Listener, DomainObjectListener, FieldLocationListener {
		final PluginTool tool;
		final Program program;
		final String module;
		final URI uri;
		final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor(r -> {
			Thread t = new Thread(r, "echodebug-sync");
			t.setDaemon(true);
			return t;
		});
		/** what both sides agree on ("name:0x10" -> value): echoes of applied values are not sent back */
		final Map<String, String> known = new ConcurrentHashMap<>();
		final StringBuilder partial = new StringBuilder();
		volatile WebSocket ws;
		volatile boolean connected;
		volatile boolean stopped;
		volatile int applying;
		volatile long lastCursor = -1;
		CompletableFuture<WebSocket> sendChain = CompletableFuture.completedFuture(null);
		FieldPanel fieldPanel;

		Session(PluginTool tool, Program program) {
			this.tool = tool;
			this.program = program;
			this.module = program.getName();
			this.uri = URI.create("ws://127.0.0.1:" + port() + "/sync");
		}

		void start() {
			program.addListener(this);
			CodeViewerService cvs = tool.getService(CodeViewerService.class);
			if (cvs != null) {
				fieldPanel = cvs.getFieldPanel();
				fieldPanel.addFieldLocationListener(this);
			}
			connect();
			timer.scheduleAtFixedRate(() -> send(obj("ping")), 15, 15, TimeUnit.SECONDS);
		}

		void stop() {
			stopped = true;
			program.removeListener(this);
			if (fieldPanel != null) {
				fieldPanel.removeFieldLocationListener(this);
			}
			WebSocket w = ws;
			if (w != null) {
				w.sendClose(WebSocket.NORMAL_CLOSURE, "bye");
			}
			timer.shutdownNow();
		}

		void connect() {
			if (stopped) {
				return;
			}
			WebSocket.Builder b = HttpClient.newHttpClient().newWebSocketBuilder().connectTimeout(Duration.ofSeconds(5));
			String t = token();
			if (t != null) {
				b.header("Authorization", "Bearer " + t);
			}
			b.buildAsync(uri, this).whenComplete((w, err) -> {
				if (err != null) {
					retry();
					return;
				}
				ws = w;
				synchronized (this) {
					sendChain = CompletableFuture.completedFuture(w);
				}
				JsonObject hello = obj("hello");
				hello.addProperty("tool", "ghidra");
				hello.addProperty("version", "Ghidra " + ghidra.framework.Application.getApplicationVersion());
				hello.addProperty("file", program.getDomainFile().getPathname());
				hello.addProperty("protocol", 1);
				JsonObject mod = new JsonObject();
				mod.addProperty("name", module);
				mod.addProperty("base", "0x" + Long.toHexString(base().getOffset()));
				JsonArray mods = new JsonArray();
				mods.add(mod);
				hello.add("modules", mods);
				w.sendText(hello.toString(), true);
			});
		}

		void retry() {
			connected = false;
			ws = null;
			if (!stopped && !timer.isShutdown()) {
				timer.schedule(this::connect, 3, TimeUnit.SECONDS);
			}
		}

		Address base() {
			return program.getImageBase();
		}

		static JsonObject obj(String type) {
			JsonObject o = new JsonObject();
			o.addProperty("type", type);
			return o;
		}

		/** Sends are chained: java.net.http.WebSocket allows one outstanding sendText. */
		synchronized void send(JsonObject o) {
			WebSocket w = ws;
			if (w == null || stopped) {
				return;
			}
			String text = o.toString();
			sendChain = sendChain.thenCompose(x -> w.sendText(text, true)).exceptionally(e -> w);
		}

		/** RVA of addr in this program, or -1 when it is outside the image. */
		long rva(Address addr) {
			if (addr == null || !addr.getAddressSpace().equals(base().getAddressSpace()) || !program.getMemory().contains(addr)) {
				return -1;
			}
			long r = addr.subtract(base());
			return r < 0 ? -1 : r;
		}

		Address addrOf(JsonObject m) {
			if (!m.has("module") || !module.equalsIgnoreCase(m.get("module").getAsString()) || !m.has("rva")) {
				return null;
			}
			try {
				String s = m.get("rva").getAsString();
				long r = Long.parseUnsignedLong(s.startsWith("0x") ? s.substring(2) : s, 16);
				return base().add(r);
			}
			catch (RuntimeException e) {
				return null;
			}
		}

		void sendMark(String kind, Address addr, String value) {
			long r = rva(addr);
			String v = value == null ? "" : value;
			if (r < 0 || !connected || applying > 0) {
				return;
			}
			String key = kind + ":" + Long.toHexString(r);
			String prev = known.get(key);
			// analysis adds and removes default symbols all the time: only clear what was synced
			if (v.equals(prev) || (v.isEmpty() && (prev == null || prev.isEmpty()))) {
				return;
			}
			known.put(key, v);
			JsonObject o = obj(kind);
			o.addProperty("module", module);
			o.addProperty("rva", "0x" + Long.toHexString(r));
			o.addProperty(kind, v);
			send(o);
		}

		// ---- WebSocket.Listener ----

		@Override
		public void onOpen(WebSocket w) {
			w.request(1);
		}

		@Override
		public CompletionStage<?> onText(WebSocket w, CharSequence data, boolean last) {
			partial.append(data);
			if (last) {
				String text = partial.toString();
				partial.setLength(0);
				try {
					JsonElement e = JsonParser.parseString(text);
					if (e.isJsonObject()) {
						handle(e.getAsJsonObject());
					}
				}
				catch (RuntimeException ex) {
					Msg.warn(EchoDebugSync.class, "EchoDebug sync: bad frame: " + ex.getMessage());
				}
			}
			w.request(1);
			return null;
		}

		@Override
		public CompletionStage<?> onClose(WebSocket w, int status, String reason) {
			if (connected) {
				Msg.info(EchoDebugSync.class, "EchoDebug sync: disconnected (" + status + " " + reason + ")");
			}
			retry();
			return null;
		}

		@Override
		public void onError(WebSocket w, Throwable error) {
			retry();
		}

		void handle(JsonObject m) {
			String type = m.has("type") ? m.get("type").getAsString() : "";
			switch (type) {
				case "hello_result":
					connected = true;
					Msg.info(EchoDebugSync.class, "EchoDebug sync: connected as ghidra (" + module + ")");
					return;
				case "error":
					Msg.warn(EchoDebugSync.class, "EchoDebug sync: relay says: " + m.get("message"));
					return;
				case "types":
					String decls = m.has("decls") ? m.get("decls").getAsString() : "";
					Swing.runLater(() -> applyTypes(decls));
					return;
				case "cursor":
				case "name":
				case "comment":
					break;
				default:
					return;
			}
			Address addr = addrOf(m);
			if (addr == null) {
				return;
			}
			if (type.equals("cursor")) {
				lastCursor = rva(addr);
				Swing.runLater(() -> applying(() -> {
					GoToService goTo = tool.getService(GoToService.class);
					if (goTo != null) {
						goTo.goTo(addr);
					}
				}));
				return;
			}
			String value = m.has(type) && !m.get(type).isJsonNull() ? m.get(type).getAsString() : "";
			known.put(type + ":" + Long.toHexString(rva(addr)), value);
			Swing.runLater(() -> applying(() -> {
				if (type.equals("name")) {
					applyName(addr, value);
				}
				else {
					transaction("EchoDebug comment", () -> program.getListing().setComment(addr, CodeUnit.EOL_COMMENT, value.isEmpty() ? null : value));
				}
			}));
		}

		void applying(Runnable r) {
			applying++;
			try {
				r.run();
			}
			catch (RuntimeException e) {
				Msg.warn(EchoDebugSync.class, "EchoDebug sync: " + e.getMessage());
			}
			finally {
				applying--;
			}
		}

		void transaction(String what, ThrowingRunnable r) {
			int tx = program.startTransaction(what);
			boolean ok = false;
			try {
				r.run();
				ok = true;
			}
			catch (Exception e) {
				Msg.warn(EchoDebugSync.class, "EchoDebug sync: " + what + " failed: " + e.getMessage());
			}
			finally {
				program.endTransaction(tx, ok);
			}
		}

		interface ThrowingRunnable {
			void run() throws Exception;
		}

		void applyName(Address addr, String name) {
			transaction("EchoDebug name", () -> {
				Function f = program.getFunctionManager().getFunctionAt(addr);
				SymbolTable st = program.getSymbolTable();
				if (name.isEmpty()) {
					if (f != null) {
						f.setName(null, SourceType.DEFAULT);
					}
					for (Symbol s : st.getSymbols(addr)) {
						if (s.getSource() == SourceType.USER_DEFINED && s.getSymbolType() == SymbolType.LABEL) {
							s.delete();
						}
					}
				}
				else if (f != null) {
					f.setName(name, SourceType.USER_DEFINED);
				}
				else {
					Symbol s = st.createLabel(addr, name, SourceType.USER_DEFINED);
					s.setPrimary();
				}
			});
		}

		void applyTypes(String decls) {
			transaction("EchoDebug types", () -> {
				DataTypeManager dtm = program.getDataTypeManager();
				CParser parser = new CParser(dtm, true, null);
				parser.parse(decls);
				Msg.info(EchoDebugSync.class, "EchoDebug sync: imported " + String.join(", ", parser.getComposites().keySet()));
			});
		}

		// ---- Ghidra -> EchoDebug ----

		@Override
		public void fieldLocationChanged(FieldLocation location, Field field, EventTrigger trigger) {
			if (applying > 0 || !connected) {
				return;
			}
			CodeViewerService cvs = tool.getService(CodeViewerService.class);
			ProgramLocation loc = cvs == null ? null : cvs.getListingPanel().getProgramLocation();
			if (loc == null || loc.getProgram() != program) {
				return;
			}
			long r = rva(loc.getAddress());
			if (r < 0 || r == lastCursor) {
				return;
			}
			lastCursor = r;
			JsonObject o = obj("cursor");
			o.addProperty("module", module);
			o.addProperty("rva", "0x" + Long.toHexString(r));
			send(o);
		}

		@Override
		public void domainObjectChanged(DomainObjectChangedEvent ev) {
			if (!connected) {
				return;
			}
			for (DomainObjectChangeRecord rec : ev) {
				if (rec.getEventType() == ProgramEvent.COMMENT_CHANGED && rec instanceof CommentChangeRecord) {
					CommentChangeRecord c = (CommentChangeRecord) rec;
					if (c.getCommentType() == CodeUnit.EOL_COMMENT) {
						sendMark("comment", c.getStart(), c.getNewComment());
					}
				}
				else if (rec.getEventType() == ProgramEvent.SYMBOL_RENAMED || rec.getEventType() == ProgramEvent.SYMBOL_ADDED ||
					rec.getEventType() == ProgramEvent.SYMBOL_REMOVED || rec.getEventType() == ProgramEvent.SYMBOL_PRIMARY_STATE_CHANGED) {
					Address addr = null;
					if (rec instanceof ProgramChangeRecord) {
						addr = ((ProgramChangeRecord) rec).getStart();
						Object o = ((ProgramChangeRecord) rec).getObject();
						if (addr == null && o instanceof Symbol) {
							addr = ((Symbol) o).getAddress();
						}
					}
					if (addr == null || !addr.isMemoryAddress()) {
						continue;
					}
					Symbol primary = program.getSymbolTable().getPrimarySymbol(addr);
					boolean user = primary != null && primary.getSource() == SourceType.USER_DEFINED;
					sendMark("name", addr, user ? primary.getName() : "");
				}
			}
		}
	}
}
