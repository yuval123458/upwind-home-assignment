const BACKEND_URL = 'https://enforced-uneven-sharpie.ngrok-free.dev';
const GMAIL_API_BASE = 'https://gmail.googleapis.com/gmail/v1/users/me';

function buildHomepageCard() {
  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Email Scorer'))
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph().setText(
            'Open an email and click "Analyze this email" to score it.'
          )
        )
        .addWidget(
          CardService.newTextButton()
            .setText('View history')
            .setOnClickAction(CardService.newAction().setFunctionName('onShowHistory'))
        )
        .addWidget(
          CardService.newTextButton()
            .setText('Manage blocklist')
            .setOnClickAction(CardService.newAction().setFunctionName('onShowBlocklist'))
        )
        .addWidget(
          CardService.newTextButton()
            .setText('Settings')
            .setOnClickAction(CardService.newAction().setFunctionName('onShowSettings'))
        )
    )
    .build();
  return [card];
}

function buildScanCard(e) {
  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Email Scorer'))
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph().setText('Click below to scan the currently open email.')
        )
        .addWidget(
          CardService.newTextButton()
            .setText('Analyze this email')
            .setOnClickAction(CardService.newAction().setFunctionName('onScanClicked'))
        )
        .addWidget(
          CardService.newTextButton()
            .setText('View history')
            .setOnClickAction(CardService.newAction().setFunctionName('onShowHistory'))
        )
        .addWidget(
          CardService.newTextButton()
            .setText('Manage blocklist')
            .setOnClickAction(CardService.newAction().setFunctionName('onShowBlocklist'))
        )
        .addWidget(
          CardService.newTextButton()
            .setText('Settings')
            .setOnClickAction(CardService.newAction().setFunctionName('onShowSettings'))
        )
    )
    .build();
  return [card];
}

function onScanClicked(e) {
  try {
    GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
    const message = GmailApp.getMessageById(e.gmail.messageId);

    const attachments = message
      .getAttachments({ includeInlineImages: false, includeAttachments: true })
      .map(function (att) {
        return {
          name: att.getName(),
          mime_type: att.getContentType(),
          size: att.getSize(),
          sha256: sha256Hex(att.getBytes()),
        };
      });

    const payload = {
      message_id: e.gmail.messageId,
      subject: message.getSubject(),
      sender: message.getFrom(),
      reply_to: message.getReplyTo() || null,
      body_plain: message.getPlainBody(),
      body_html: message.getBody(),
      authentication_results: message.getHeader('Authentication-Results') || null,
      attachments: attachments,
    };

    const response = UrlFetchApp.fetch(BACKEND_URL + '/score', {
      method: 'post',
      contentType: 'application/json',
      headers: backendHeaders(),
      payload: JSON.stringify(payload),
      muteHttpExceptions: true,
    });

    const code = response.getResponseCode();
    const body = response.getContentText();

    if (code !== 200) {
      return CardService.newActionResponseBuilder()
        .setNotification(
          CardService.newNotification().setText('Backend ' + code + ': ' + body.substring(0, 140))
        )
        .build();
    }

    const result = JSON.parse(body);
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().pushCard(buildResultCard(result, payload.sender)))
      .build();
  } catch (err) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText('Error: ' + err.message))
      .build();
  }
}

function friendlySignalLabel(name) {
  const labels = {
    auth_headers: 'Authentication failed',
    url_reputation: 'Suspicious link(s)',
    llm_content: 'Content analysis',
    attachment_reputation: 'Malicious attachment(s)',
    blocklist: 'Sender on your blocklist',
    reply_to_mismatch: 'Reply-To mismatch',
    link_anchor_mismatch: 'Link text vs destination mismatch',
    domain_age: 'Sender domain age',
  };
  return labels[name] || name;
}

function buildResultCard(result, sender) {
  const bandConfig = {
    safe:       { icon: '✓', title: 'Looks safe' },
    suspicious: { icon: '⚠',  title: 'Suspicious' },
    malicious: { icon: '⛔',  title: 'Likely phishing' },
  };
  const cfg = bandConfig[result.band] || { icon: '?', title: result.band };

  const builder = CardService.newCardBuilder().setHeader(
    CardService.newCardHeader()
      .setTitle(cfg.icon + '  ' + cfg.title)
      .setSubtitle('Score ' + result.score + ' / 100')
  );

  if (result.band === 'safe') {
    builder.addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText(
          'No suspicious findings. Sender authenticated, links and attachments look clean.'
        )
      )
    );
  } else {
    const section = CardService.newCardSection().setHeader('Why');
    result.signals
      .filter(function (s) { return s.points > 0; })
      .forEach(function (s) {
        section.addWidget(
          CardService.newKeyValue()
            .setTopLabel(friendlySignalLabel(s.name))
            .setContent(s.evidence)
            .setMultiline(true)
        );
      });
    builder.addSection(section);

    if (result.recommendation) {
      builder.addSection(
        CardService.newCardSection()
          .setHeader('Recommendation')
          .addWidget(CardService.newTextParagraph().setText(result.recommendation))
      );
    }
  }

  if (result.sender_history && result.sender_history.scan_count > 0) {
    const sh = result.sender_history;
    const bandWord = sh.last_band ? sh.last_band[0].toUpperCase() + sh.last_band.substring(1) : 'unknown';
    builder.addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText(
          'You\'ve scanned this sender ' + sh.scan_count + ' time(s) before — last: ' + bandWord + '.'
        )
      )
    );
  }

  if (sender) {
    builder.addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextButton()
          .setText('Block sender')
          .setOnClickAction(
            CardService.newAction()
              .setFunctionName('onBlockClicked')
              .setParameters({ sender: sender })
          )
      )
    );
  }

  return builder.build();
}

function onBlockClicked(e) {
  try {
    const raw = e.parameters.sender;
    const match = /[\w.+-]+@[\w-]+\.[\w.-]+/.exec(raw);
    const email = match ? match[0].toLowerCase() : raw.toLowerCase();

    const filterId = gmailCreateFilter(email);
    backendAddBlocklist(email, filterId);

    return CardService.newActionResponseBuilder()
      .setNotification(
        CardService.newNotification().setText(
          'Blocked ' + email + '. Future emails go to Trash.'
        )
      )
      .build();
  } catch (err) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText('Block failed: ' + err.message))
      .build();
  }
}

function onShowHistory(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(buildHistoryCard()))
    .build();
}

function buildHistoryCard() {
  let entries;
  try {
    entries = backendListHistory(20);
  } catch (err) {
    return CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle('Scan history'))
      .addSection(
        CardService.newCardSection().addWidget(
          CardService.newTextParagraph().setText('Error loading history: ' + err.message)
        )
      )
      .build();
  }

  const bandIcons = { safe: '✓', suspicious: '⚠', malicious: '⛔' };
  const card = CardService.newCardBuilder().setHeader(
    CardService.newCardHeader().setTitle('Scan history').setSubtitle(entries.length + ' recent scans')
  );

  if (entries.length === 0) {
    card.addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText(
          'No scans yet. Open an email and click "Analyze this email" to start.'
        )
      )
    );
  } else {
    const section = CardService.newCardSection();
    entries.forEach(function (entry) {
      const icon = bandIcons[entry.band] || '?';
      const subject = entry.subject || '(no subject)';
      const truncated = subject.length > 45 ? subject.substring(0, 42) + '...' : subject;
      const when = entry.scanned_at ? entry.scanned_at.substring(0, 16).replace('T', ' ') : '';
      section.addWidget(
        CardService.newKeyValue()
          .setTopLabel(icon + '  ' + truncated)
          .setContent((entry.sender || '(unknown)') + ' · ' + when + ' · score ' + entry.score)
          .setMultiline(true)
      );
    });
    card.addSection(section);
  }
  return card.build();
}

function onShowBlocklist(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(buildBlocklistCard()))
    .build();
}

function buildBlocklistCard() {
  let entries;
  try {
    entries = backendListBlocklist();
  } catch (err) {
    return CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle('Blocklist'))
      .addSection(
        CardService.newCardSection().addWidget(
          CardService.newTextParagraph().setText('Error loading blocklist: ' + err.message)
        )
      )
      .build();
  }

  const card = CardService.newCardBuilder().setHeader(
    CardService.newCardHeader().setTitle('Blocklist').setSubtitle(entries.length + ' entries')
  );

  if (entries.length === 0) {
    card.addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText(
          'No blocked senders yet. Block one from a scan result.'
        )
      )
    );
  } else {
    const section = CardService.newCardSection();
    entries.forEach(function (entry) {
      section.addWidget(
        CardService.newKeyValue()
          .setTopLabel(entry.value)
          .setContent(entry.gmail_filter_id ? 'Filter active in Gmail' : 'No filter (backend only)')
          .setButton(
            CardService.newTextButton()
              .setText('Unblock')
              .setOnClickAction(
                CardService.newAction()
                  .setFunctionName('onUnblockClicked')
                  .setParameters({
                    entryId: String(entry.id),
                    filterId: entry.gmail_filter_id || '',
                  })
              )
          )
      );
    });
    card.addSection(section);
  }
  return card.build();
}

function onUnblockClicked(e) {
  try {
    const entryId = parseInt(e.parameters.entryId, 10);
    const filterId = e.parameters.filterId;

    if (filterId) {
      gmailDeleteFilter(filterId);
    }
    backendRemoveBlocklist(entryId);

    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText('Unblocked.'))
      .setNavigation(CardService.newNavigation().updateCard(buildBlocklistCard()))
      .build();
  } catch (err) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText('Unblock failed: ' + err.message))
      .build();
  }
}

function onShowSettings(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(buildSettingsCard()))
    .build();
}

function buildSettingsCard() {
  let settings;
  try {
    settings = backendGetSettings();
  } catch (err) {
    return CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle('Settings'))
      .addSection(
        CardService.newCardSection().addWidget(
          CardService.newTextParagraph().setText('Error loading settings: ' + err.message)
        )
      )
      .build();
  }

  const current = settings.sensitivity;
  const descriptions = {
    low: 'LOW — fewer flags; only strong evidence shifts the verdict.',
    medium: 'MEDIUM — balanced default.',
    high: 'HIGH — small signals can shift the band; more flags overall.',
  };

  const card = CardService.newCardBuilder().setHeader(
    CardService.newCardHeader().setTitle('Settings').setSubtitle('Detection sensitivity')
  );

  const summary = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph().setText(
        'Current: <b>' + current.toUpperCase() + '</b>'
      )
    )
    .addWidget(CardService.newTextParagraph().setText(descriptions[current] || ''));
  card.addSection(summary);

  const buttons = CardService.newCardSection().setHeader('Change sensitivity');
  ['low', 'medium', 'high'].forEach(function (level) {
    const label = level === current ? '✓ ' + level.toUpperCase() : level.toUpperCase();
    buttons.addWidget(
      CardService.newTextButton()
        .setText(label)
        .setOnClickAction(
          CardService.newAction()
            .setFunctionName('onSensitivityChanged')
            .setParameters({ sensitivity: level })
        )
    );
  });
  card.addSection(buttons);

  return card.build();
}

function onSensitivityChanged(e) {
  try {
    backendUpdateSettings(e.parameters.sensitivity);
    return CardService.newActionResponseBuilder()
      .setNotification(
        CardService.newNotification().setText('Sensitivity set to ' + e.parameters.sensitivity)
      )
      .setNavigation(CardService.newNavigation().updateCard(buildSettingsCard()))
      .build();
  } catch (err) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText('Update failed: ' + err.message))
      .build();
  }
}

function sha256Hex(bytes) {
  const digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes);
  return digest
    .map(function (b) {
      return ((b < 0 ? b + 256 : b) & 0xff).toString(16);
    })
    .map(function (s) {
      return s.length === 1 ? '0' + s : s;
    })
    .join('');
}

function backendHeaders() {
  return {
    Authorization: 'Bearer ' + ScriptApp.getIdentityToken(),
    'ngrok-skip-browser-warning': 'true',
  };
}

function gmailHeaders() {
  return { Authorization: 'Bearer ' + ScriptApp.getOAuthToken() };
}

function gmailCreateFilter(senderEmail) {
  const body = {
    criteria: { from: senderEmail },
    action: { addLabelIds: ['TRASH'] },
  };
  const response = UrlFetchApp.fetch(GMAIL_API_BASE + '/settings/filters', {
    method: 'post',
    contentType: 'application/json',
    headers: gmailHeaders(),
    payload: JSON.stringify(body),
    muteHttpExceptions: true,
  });
  if (response.getResponseCode() !== 200) {
    throw new Error('Gmail create filter failed: ' + response.getContentText());
  }
  return JSON.parse(response.getContentText()).id;
}

function gmailDeleteFilter(filterId) {
  const response = UrlFetchApp.fetch(
    GMAIL_API_BASE + '/settings/filters/' + filterId,
    { method: 'delete', headers: gmailHeaders(), muteHttpExceptions: true }
  );
  const code = response.getResponseCode();
  if (code !== 204 && code !== 404) {
    throw new Error('Gmail delete filter failed: ' + code + ' ' + response.getContentText());
  }
}

function backendAddBlocklist(senderEmail, filterId) {
  const response = UrlFetchApp.fetch(BACKEND_URL + '/blocklist', {
    method: 'post',
    contentType: 'application/json',
    headers: backendHeaders(),
    payload: JSON.stringify({ value: senderEmail, gmail_filter_id: filterId }),
    muteHttpExceptions: true,
  });
  if (response.getResponseCode() >= 300) {
    throw new Error('Backend add failed: ' + response.getContentText());
  }
  return JSON.parse(response.getContentText());
}

function backendGetSettings() {
  const response = UrlFetchApp.fetch(BACKEND_URL + '/settings', {
    method: 'get',
    headers: backendHeaders(),
    muteHttpExceptions: true,
  });
  if (response.getResponseCode() >= 300) {
    throw new Error('Backend settings GET failed: ' + response.getContentText());
  }
  return JSON.parse(response.getContentText());
}

function backendUpdateSettings(sensitivity) {
  const response = UrlFetchApp.fetch(BACKEND_URL + '/settings', {
    method: 'patch',
    contentType: 'application/json',
    headers: backendHeaders(),
    payload: JSON.stringify({ sensitivity: sensitivity }),
    muteHttpExceptions: true,
  });
  if (response.getResponseCode() >= 300) {
    throw new Error('Backend settings PATCH failed: ' + response.getContentText());
  }
  return JSON.parse(response.getContentText());
}

function backendListHistory(limit) {
  const url = BACKEND_URL + '/history?limit=' + (limit || 20);
  const response = UrlFetchApp.fetch(url, {
    method: 'get',
    headers: backendHeaders(),
    muteHttpExceptions: true,
  });
  if (response.getResponseCode() >= 300) {
    throw new Error('Backend history failed: ' + response.getContentText());
  }
  return JSON.parse(response.getContentText());
}

function backendListBlocklist() {
  const response = UrlFetchApp.fetch(BACKEND_URL + '/blocklist', {
    method: 'get',
    headers: backendHeaders(),
    muteHttpExceptions: true,
  });
  if (response.getResponseCode() >= 300) {
    throw new Error('Backend list failed: ' + response.getContentText());
  }
  return JSON.parse(response.getContentText());
}

function backendRemoveBlocklist(entryId) {
  const response = UrlFetchApp.fetch(BACKEND_URL + '/blocklist/' + entryId, {
    method: 'delete',
    headers: backendHeaders(),
    muteHttpExceptions: true,
  });
  const code = response.getResponseCode();
  if (code >= 300 && code !== 404) {
    throw new Error('Backend remove failed: ' + response.getContentText());
  }
}
