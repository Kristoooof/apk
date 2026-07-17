package com.ep2pc.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.Group
import androidx.compose.material.icons.filled.GroupAdd
import androidx.compose.material.icons.filled.PersonAdd
import androidx.compose.material.icons.filled.QrCode
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.ep2pc.core.NativeBridge
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

private enum class Screen { List, Chat, Contacts, Settings }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun Ep2pcApp(vm: ChatViewModel = viewModel()) {
    var screen by remember { mutableStateOf(Screen.List) }
    var openId by remember { mutableStateOf<String?>(null) }
    var showNewGroup by remember { mutableStateOf(false) }

    when (screen) {
        Screen.List -> ConversationList(
            items = vm.conversations,
            onOpen = { openId = it.id; screen = Screen.Chat },
            onContacts = { screen = Screen.Contacts },
            onNewGroup = { showNewGroup = true },
            onSettings = { screen = Screen.Settings }
        )
        Screen.Chat -> {
            val id = openId
            val conv = vm.conversations.firstOrNull { it.id == id }
            if (id != null && conv != null) {
                ChatScreen(
                    conversation = conv,
                    messages = vm.messagesFor(id),
                    contacts = if (conv.isGroup) vm.contacts() else emptyList(),
                    onSend = { vm.send(id, it) },
                    onAddMember = { memberId -> vm.addMember(id, memberId) },
                    onBack = { screen = Screen.List }
                )
            } else screen = Screen.List
        }
        Screen.Contacts -> ContactsScreen(
            onBack = { screen = Screen.List },
            onContactAdded = { peerId -> vm.addContact(peerId, "Új kontakt"); screen = Screen.List }
        )
        Screen.Settings -> SettingsScreen(onBack = { screen = Screen.List })
    }

    if (showNewGroup) {
        NewGroupDialog(
            onDismiss = { showNewGroup = false },
            onCreate = { name -> vm.createGroup(name); showNewGroup = false }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ConversationList(
    items: List<Conversation>,
    onOpen: (Conversation) -> Unit,
    onContacts: () -> Unit,
    onNewGroup: () -> Unit,
    onSettings: () -> Unit
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("EP2PC") },
                actions = {
                    IconButton(onClick = onNewGroup) {
                        Icon(Icons.Filled.GroupAdd, contentDescription = "Új csoport")
                    }
                    IconButton(onClick = onSettings) {
                        Icon(Icons.Filled.Settings, contentDescription = "Beállítások")
                    }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = onContacts) {
                Icon(Icons.Filled.PersonAdd, contentDescription = "Kontaktok")
            }
        }
    ) { padding ->
        if (items.isEmpty()) {
            Box(Modifier.padding(padding).fillMaxSize(), contentAlignment = Alignment.Center) {
                Text("Még nincs beszélgetés.\nAdj hozzá egy kontaktot a + gombbal,\nvagy hozz létre csoportot.", textAlign = TextAlign.Center)
            }
        } else {
            LazyColumn(Modifier.padding(padding).fillMaxSize()) {
                items(items) { c ->
                    ListItem(
                        leadingContent = { if (c.isGroup) Icon(Icons.Filled.Group, contentDescription = null) },
                        headlineContent = { Text(c.name) },
                        supportingContent = { Text(if (c.lastMessage.isBlank()) "—" else c.lastMessage) },
                        trailingContent = { if (c.online) Text("●", color = MaterialTheme.colorScheme.primary) },
                        modifier = Modifier.fillMaxWidth().heightIn(min = 64.dp).clickable { onOpen(c) }
                    )
                    HorizontalDivider()
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ContactsScreen(onBack: () -> Unit, onContactAdded: (ByteArray) -> Unit) {
    var showMyQr by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf<String?>(null) }

    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        val contents = result.contents ?: run { status = "Beolvasás megszakítva"; return@rememberLauncherForActivityResult }
        val bundle = QrCodec.decodeBundle(contents) ?: run { status = "Érvénytelen QR-kód"; return@rememberLauncherForActivityResult }
        val peerId = NativeBridge.addContact(bundle)
        if (peerId == null) status = "A kontakt hozzáadása sikertelen (érvénytelen aláírás?)"
        else onContactAdded(peerId)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Kontakt hozzáadása") },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Vissza") }
                }
            )
        }
    ) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize().padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text(
                "Cseréljétek ki a QR-kódotokat: az egyik fél mutatja, a másik beolvassa. " +
                    "A QR csak nyilvános kulcsot tartalmaz – a session titkosítva jön létre.",
                textAlign = TextAlign.Center
            )
            Button(onClick = { showMyQr = true }, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Filled.QrCode, contentDescription = null); Spacer(Modifier.width(8.dp)); Text("Saját QR-kód megjelenítése")
            }
            Button(onClick = { scanLauncher.launch(scanOptions()) }, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Filled.QrCodeScanner, contentDescription = null); Spacer(Modifier.width(8.dp)); Text("Kontakt QR beolvasása")
            }
            status?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        }
    }

    if (showMyQr) MyQrDialog(onDismiss = { showMyQr = false })
}

@Composable
private fun MyQrDialog(onDismiss: () -> Unit) {
    val bitmap = remember {
        runCatching { QrCodec.qrBitmap(QrCodec.encodeBundle(NativeBridge.myBundle())) }.getOrNull()
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = { TextButton(onClick = onDismiss) { Text("Bezár") } },
        title = { Text("A te QR-kódod") },
        text = {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                if (bitmap != null) {
                    Image(bitmap = bitmap.asImageBitmap(), contentDescription = "Saját QR-kód", modifier = Modifier.size(260.dp))
                } else Text("A QR-kód nem elérhető (a core még nem indult el).")
                Spacer(Modifier.height(8.dp))
                Text("Olvastasd be a másik eszközzel a kontakt hozzáadásához.", textAlign = TextAlign.Center)
            }
        }
    )
}

@Composable
private fun NewGroupDialog(onDismiss: () -> Unit, onCreate: (String) -> Unit) {
    var name by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = { TextButton(enabled = name.isNotBlank(), onClick = { onCreate(name) }) { Text("Létrehozás") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Mégse") } },
        title = { Text("Új csoport") },
        text = {
            OutlinedTextField(value = name, onValueChange = { name = it }, label = { Text("Csoport neve") }, singleLine = true)
        }
    )
}

@Composable
private fun AddMemberDialog(contacts: List<Conversation>, onDismiss: () -> Unit, onPick: (String) -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {},
        dismissButton = { TextButton(onClick = onDismiss) { Text("Bezár") } },
        title = { Text("Tag hozzáadása") },
        text = {
            if (contacts.isEmpty()) {
                Text("Nincs hozzáadható kontakt. Előbb vegyél fel kontaktot QR-kóddal.")
            } else {
                LazyColumn {
                    items(contacts) { c ->
                        ListItem(
                            headlineContent = { Text(c.name) },
                            modifier = Modifier.fillMaxWidth().clickable { onPick(c.id) }
                        )
                        HorizontalDivider()
                    }
                }
            }
        }
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ChatScreen(
    conversation: Conversation,
    messages: List<ChatMessage>,
    contacts: List<Conversation>,
    onSend: (String) -> Unit,
    onAddMember: (String) -> Unit,
    onBack: () -> Unit
) {
    var draft by remember { mutableStateOf("") }
    var showAddMember by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(conversation.name) },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Vissza") }
                },
                actions = {
                    if (conversation.isGroup) {
                        IconButton(onClick = { showAddMember = true }) {
                            Icon(Icons.Filled.PersonAdd, contentDescription = "Tag hozzáadása")
                        }
                    }
                }
            )
        },
        bottomBar = {
            Row(Modifier.fillMaxWidth().padding(8.dp), verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = draft, onValueChange = { draft = it },
                    modifier = Modifier.weight(1f), placeholder = { Text("Üzenet…") }
                )
                Spacer(Modifier.width(8.dp))
                FilledIconButton(onClick = { if (draft.isNotBlank()) { onSend(draft); draft = "" } }) {
                    Icon(Icons.AutoMirrored.Filled.Send, contentDescription = "Küldés")
                }
            }
        }
    ) { padding ->
        LazyColumn(Modifier.padding(padding).fillMaxSize().padding(horizontal = 12.dp)) {
            items(messages) { m -> MessageBubble(m) }
        }
    }

    if (showAddMember) {
        AddMemberDialog(
            contacts = contacts,
            onDismiss = { showAddMember = false },
            onPick = { memberId -> onAddMember(memberId); showAddMember = false }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SettingsScreen(onBack: () -> Unit) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var relay by remember { mutableStateOf(com.ep2pc.core.Settings.getRelay(context)) }
    var saved by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Beállítások") },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Vissza") }
                }
            )
        }
    ) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize().padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text("Relay / szerver cím", style = MaterialTheme.typography.titleMedium)
            Text(
                "A VPS-eden futó EP2PC relay címe. Ezen keresztül találják meg egymást a " +
                    "telefonok és megy át az üzenet akkor is, ha nincsenek egy WiFi-n. " +
                    "A relay a titkosított adatot csak továbbítja, nem látja.",
                style = MaterialTheme.typography.bodySmall
            )
            OutlinedTextField(
                value = relay,
                onValueChange = { relay = it; saved = false },
                modifier = Modifier.fillMaxWidth(),
                singleLine = false,
                label = { Text("/ip4/<VPS-IP>/tcp/4001/p2p/12D3Koo...") }
            )
            Button(
                onClick = {
                    com.ep2pc.core.Settings.setRelay(context, relay)
                    saved = true
                },
                modifier = Modifier.fillMaxWidth()
            ) { Text("Mentés") }

            if (saved) {
                Text(
                    "Elmentve. A változás életbe lépéséhez zárd be teljesen és indítsd újra az appot " +
                        "(a legutóbbi appok közül is húzd ki).",
                    color = MaterialTheme.colorScheme.primary,
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}

@Composable
private fun MessageBubble(m: ChatMessage) {
    val align = if (m.mine) Alignment.End else Alignment.Start
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp), horizontalAlignment = align) {
        Surface(
            color = if (m.mine) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceVariant,
            shape = MaterialTheme.shapes.medium
        ) {
            Text(
                m.body,
                Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                color = if (m.mine) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Start
            )
        }
    }
}

private fun scanOptions() = ScanOptions().apply {
    setDesiredBarcodeFormats(ScanOptions.QR_CODE)
    setPrompt("Olvasd be a kontakt QR-kódját")
    setBeepEnabled(false)
    setOrientationLocked(false)
}
